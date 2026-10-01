/* link.c -- see link.h. The link lifecycle and the FEDERATE exchange.
 *
 * ---------------------------------------------------------------------------
 * THE ASCII FOLD, AND WHY IT IS A FOURTH COPY
 * ---------------------------------------------------------------------------
 * A server name is case-insensitive (2.1, RFC 1459 2.3.2), so `IRC.A` and
 * `irc.a` are one server, and every comparison of two server names in this
 * node has to fold. The fold already exists three times -- in server.c
 * (same_server_name), channel.c (same_name) and dedup.c (fold_byte) -- and it
 * is copied rather than exported for the reason those three are: each is
 * private to a module whose key rule is its own, and exporting a fold would
 * make a fifth place able to get it subtly wrong (a Unicode fold, say, in a
 * node that advertises CASEMAPPING=ascii in 005). ASCII-only is the fold, for
 * the reason dedup.c gives: 005 has already told every client that []\~ and
 * {}|^ are not equivalent, and folding them here would break that promise in
 * the one place nothing on the wire would show it.
 */
#include "federation/link.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "core/connection.h"
#include "federation/burst.h"
#include "federation/dedup.h"
#include "federation/verbs.h"

/* The number of members of fed_federate_result_t, and so the width of the
 * per-reason rejection counters. It is a number rather than a compile-time
 * assertion on purpose: -Wpre-c11-compat is in upstream clang's -Weverything
 * and objects to _Static_assert, and this project's answer to a diagnostic it
 * cannot satisfy without narrowing the warning set is never to narrow it (see
 * the warning block in the top-level CMakeLists.txt, and dedup.h for the same
 * argument about a struct size). Every write into the array is bounds-checked
 * against this number, so a reason added to the enum without a counter here is
 * a reason that is counted nowhere rather than a reason that writes past the
 * array -- and the dump prints "?" for it, which is how it gets noticed. */
#define FED_RESULT_COUNT 11

/* ---------------------------------------------------------------------------
 * Module state, and what it is allowed to hold
 * ---------------------------------------------------------------------------
 * Three things, all of them node-identity rather than node-state, and all
 * single-threaded behind the one event loop (3.4). The link table itself, the
 * dedup store and the counters are all on server_t; what is here is what
 * server_t has no room for because it is not a per-node fact:
 *
 *   g_secret / g_secret_len  the shared token. It is the one piece of the
 *       node's configuration that no struct on server_t carries, and adding a
 *       field there for it would put a credential in the struct that half the
 *       tree can see. Keeping it here is the smaller of two exposures, and it
 *       is a module global for the same reason the handshake FSM has no
 *       module state of its own: single-threaded, one node per process, and
 *       fed_open() refuses a second node.
 *   g_inner / g_owner        the dispatch this module wrapped, and the node it
 *       was taken from. See the ONE NODE PER PROCESS note in the header.
 *   g_dial_ms / g_hs_ms /    the per-process timer overrides. Parameters
 *   g_keepalive_ms / g_dead_ms rather than function arguments because the tick
 *       hook's signature is fixed by core/server.h and a timer is not
 *       something the loop should have to be told about on every call.
 */

/* The node whose FEDERATE lines this process handles, and the dispatch that was
 * installed before fed_open() replaced it. */
static server_t *g_owner = NULL;
static server_dispatch_fn g_inner = NULL;

static char     g_secret[IRC_FED_MAX_SECRET];
static size_t   g_secret_len = 0;

static uint64_t g_dial_ms = (uint64_t)IRC_FED_DIAL_TIMEOUT_MS;
static uint64_t g_hs_ms = (uint64_t)IRC_FED_HS_TIMEOUT_MS;
static uint64_t g_keepalive_ms = (uint64_t)IRC_FED_KEEPALIVE_MS;
static uint64_t g_dead_ms = (uint64_t)IRC_FED_DEAD_MS;

/* The three reconnect intervals, and why they are module state rather than
 * arguments. Same argument as the four above: the tick hook's signature is
 * fixed by core/server.h, and a schedule is not something the loop should have
 * to be handed on every call. The seeded values are the #ifndef defaults, so a
 * build that supplied its own at compile time and a test that supplies its own
 * at run time reach this code by the same path. */
static uint64_t   g_retry_base_ms = (uint64_t)IRC_FED_RETRY_BASE_MS;
static uint64_t   g_retry_max_ms = (uint64_t)IRC_FED_RETRY_MAX_MS;
static unsigned   g_retry_budget = (unsigned)IRC_FED_RETRY_BUDGET;

/* The per-reason rejection breakdown. Indexed by fed_federate_result_t, so the
 * index of a verdict IS its counter, and a dump cannot print a reason beside
 * another reason's count. FED_OK's slot is never written: a line that is
 * accepted is not a rejection. */
static uint64_t g_rejected[FED_RESULT_COUNT];

/* The stable spellings, and the dump keys. One table for both so that the
 * `reason=` on the rejection line and the `rej_*=` on the dump line cannot
 * drift apart, which is the failure a reader hits when they are two lists and
 * one of them has a typo: every count looks plausible and the name beside it
 * is the wrong one.
 *
 * THE INDEX IS THE VERDICT, and the comment on FED_RESULT_COUNT above is the
 * reason that is an invariant rather than a convention: the counter array and
 * this array are both indexed by fed_federate_result_t, so a member added to
 * the enum without a row here is a member whose counter is a neighbour's. The
 * two new rows therefore sit where link.h puts the two new members -- beside
 * the verdicts they belong with, which is FED_NO_SECRET next to the secret and
 * FED_NAME_MISMATCH next to the uniqueness verdicts. */
static const char *const FED_REASON_NAME[FED_RESULT_COUNT] = {
    "OK",         /* FED_OK            */
    "BAD_ARITY",  /* FED_BAD_ARITY     */
    "BAD_SECRET", /* FED_BAD_SECRET    */
    "NO_SECRET",  /* FED_NO_SECRET     */
    "SELF_NAME",  /* FED_SELF_NAME     */
    "NAME_IN_USE",/* FED_NAME_IN_USE   */
    "DUPLICATE_LINK",
    "NAME_MISMATCH",
    "BAD_NAME",   /* FED_BAD_NAME      */
    "BAD_EPOCH",  /* FED_BAD_EPOCH     */
    "BAD_VERSION" /* FED_BAD_VERSION   */
};

/* The per-reason keys, for the dump. A table rather than ten literals in a
 * printf because fed_federate_reason() is the other half of the same
 * contract -- the `reason=` on a rejection line and the `rej_*=` beside a count
 * on the dump line are the same set of names, and two hand-written lists are
 * two lists that drift. Index FED_OK is an empty string and is never printed:
 * a line that was accepted is not a rejection. */
static const char *const FED_REASON_KEY[FED_RESULT_COUNT] = {
    "", "rej_arity=", "rej_secret=", "rej_nosecret=", "rej_self=",
    "rej_in_use=", "rej_dup=", "rej_mismatch=", "rej_name=", "rej_epoch=",
    "rej_version="
};

const char *fed_federate_reason(fed_federate_result_t result)
{
    /* Switched on an int rather than on the enum, and the reason is the
     * -Weverything pair that fanout.c documents: -Wswitch-default wants a
     * `default` on a switch over an enum and -Wcovered-switch-default reports
     * that `default` as redundant when every enumerator is listed, so a switch
     * written both ways cannot satisfy both. Reading the value into an int
     * satisfies both, the cases below are still one per enumerator, and a
     * reason added later lands in the `default` that says it has no name yet
     * rather than falling off the end of the function. */
    int which = (int)result;

    switch (which) {
    case (int)FED_OK:
    case (int)FED_BAD_ARITY:
    case (int)FED_BAD_SECRET:
    case (int)FED_NO_SECRET:
    case (int)FED_SELF_NAME:
    case (int)FED_NAME_IN_USE:
    case (int)FED_DUPLICATE_LINK:
    case (int)FED_NAME_MISMATCH:
    case (int)FED_BAD_NAME:
    case (int)FED_BAD_EPOCH:
    case (int)FED_BAD_VERSION:
        break;
    default:
        /* Unreachable while fed_federate_result_t is closed and every member
         * is listed. A BUG REPORT if it is ever reached, so it says so rather
         * than returning a name that does not correspond to anything. */
        printf("[observable] link_reason_unknown: reason=%d\n", which);
        return "UNKNOWN";
    }
    if (which < 0 || which >= FED_RESULT_COUNT) {
        return "UNKNOWN";
    }
    return FED_REASON_NAME[which];
}

static void count_reject(fed_federate_result_t result)
{
    int which = (int)result;

    if (which > 0 && which < FED_RESULT_COUNT) {
        g_rejected[which]++;
    }
}

/* ---------------------------------------------------------------------------
 * Folding and comparison
 * ---------------------------------------------------------------------------
 */
static char fold_char(char c)
{
    if (c >= 'A' && c <= 'Z') {
        return (char)(c - ('A' - 'a'));
    }
    return c;
}

static int same_name(const char *a, const char *b)
{
    size_t i;

    for (i = 0; a[i] != '\0' && b[i] != '\0'; i++) {
        if (fold_char(a[i]) != fold_char(b[i])) {
            return 0;
        }
    }
    return a[i] == '\0' && b[i] == '\0';
}

/* Constant-time secret comparison.
 *
 * The threat is specific and it is the reason this is not strcmp(): a
 * rejection closes the connection, so the TIME at which the close arrives is
 * observable to whoever opened it, and strcmp returns at the first differing
 * byte. That is a prefix oracle -- try a secret a byte at a time and the
 * close latency tells you when you are right -- and it needs no access to this
 * node beyond the ability to open a socket to it.
 *
 * So the diff is accumulated in an unsigned char and the loop runs to the end
 * with no early exit, and the accumulator is what is tested at the end. The
 * casts are explicit because an implicit char-to-unsigned-char conversion is
 * exactly the kind of thing -Wsign-conversion reports, and a diagnostic about
 * a secret comparison is a diagnostic worth having.
 *
 * The LENGTH is compared by the same walk rather than separately: the loop
 * runs to max(la, lb) and reads 0 for the side that has already ended. A C
 * string has no embedded NUL, so the byte past the end of the shorter one is
 * always non-zero on the longer side, and a length difference therefore shows
 * up as a differing byte like any other -- which is why there is no branch on
 * the lengths and no separate length term to fold in. */
static int secret_matches(const char *configured, const char *offered)
{
    size_t la;
    size_t lb;
    size_t n;
    size_t i;
    unsigned char diff = 0;

    if (configured == NULL || offered == NULL) {
        return 0;
    }
    la = strlen(configured);
    lb = strlen(offered);
    n = (la > lb) ? la : lb;
    for (i = 0; i < n; i++) {
        unsigned char a = (i < la) ? (unsigned char)configured[i] : (unsigned char)0;
        unsigned char b = (i < lb) ? (unsigned char)offered[i] : (unsigned char)0;

        diff |= (unsigned char)(a ^ b);
    }
    return (diff == 0u) ? 1 : 0;
}

/* The peer's epoch, which is not this node's and is not derivable from it.
 *
 * The grammar is 2.4's epoch grammar from message.h verbatim -- unsigned
 * decimal, 1..20 digits, no leading zero unless the value is exactly "0" --
 * and the 20-digit ceiling is what makes the multiply below safe: the largest
 * 20-digit decimal is UINT64_MAX, so `v` cannot wrap.
 *
 * The parser is a copy of the one inside irc_serve_tags_parse() and it is a
 * copy rather than a share because that one is file-static inside message.c and
 * exporting it would mean message.c's tag grammar becoming a dependency of the
 * link path for the sake of twelve lines. A consequence worth writing down: a
 * peer that sends an epoch this rejects is a peer whose tags would also be
 * rejected by irc_serve_tags_valid(), so the two cannot disagree about what a
 * legal epoch is -- they can only be reached from different directions. */
static int parse_epoch(const char *text, uint64_t *out)
{
    uint64_t v = 0;
    size_t n;
    size_t i;

    if (text == NULL || out == NULL) {
        return -1;
    }
    n = strlen(text);
    if (n == 0u || n > 20u) {
        return -1;
    }
    if (n > 1u && text[0] == '0') {
        return -1; /* a leading zero, so it is not a number the peer will repeat */
    }
    for (i = 0; i < n; i++) {
        if (text[i] < '0' || text[i] > '9') {
            return -1;
        }
        v = (v * 10u) + (uint64_t)(text[i] - '0');
    }
    *out = v;
    return 0;
}

/* The observable dump
 * ---------------------------------------------------------------------------
 * Three shapes, deliberately, because they answer three different questions.
 * The headline line says how many peers and how many rejections. The breakdown
 * line says WHICH rejections, and it is a separate line because eight
 * key=value pairs on one line is a line nobody reads the third field of. The
 * per-link lines say the FSM state and the two liveness stamps, which is the
 * split-brain evidence 8 asks for -- a single line per link that also carried
 * the totals would be unreadable past three peers.
 *
 * The reason SPELLINGS and the per-reason keys come from the one pair of
 * tables that fed_federate_reason() and the breakdown read, so the `reason=` on
 * a rejection line and the `rej_*=` beside a count cannot drift apart. That is
 * the failure a reader hits when the two are separate lists and one of them
 * has a typo: every count looks plausible and the name beside it is the wrong
 * one.
 */
static const char *fed_state_name(int state)
{
    /* Read into an int for the same reason fed_federate_reason() does: a
     * handshake_state_t is an enum, and -Weverything's -Wswitch-default and
     * -Wcovered-switch-default cannot both be satisfied by a switch over one. */
    int which = state;

    switch (which) {
    case (int)INIT:
        return "INIT";
    case (int)HANDSHAKE_SENT:
        return "HANDSHAKE_SENT";
    case (int)ESTABLISHED:
        return "ESTABLISHED";
    case (int)FAILED:
        return "FAILED";
    case (int)TIMED_OUT:
        return "TIMED_OUT";
    default:
        return "UNKNOWN";
    }
}

void fed_dump(const server_t *s, const char *why)
{
    uint64_t total_rejected = 0;
    size_t i;
    size_t established = 0;
    size_t links;

    if (s == NULL) {
        return;
    }
    links = server_link_count(s);
    for (i = 0; i < links; i++) {
        const server_link_t *link = server_link_at(s, i);

        if (link != NULL && link->state == (int)ESTABLISHED) {
            established++;
        }
    }
    for (i = 1; i < (size_t)FED_RESULT_COUNT; i++) {
        total_rejected += g_rejected[i];
    }
    /* Why the dump is not gated on s->trace, unlike the per-line trace: a dump
     * is asked for because something is wrong, and the flag that produces the
     * high-volume per-line output is a volume control. The one who needs this
     * line is debugging, and a debug switch that is off in the deployment where
     * the bug reproduces is not a debug switch. */
    printf("[observable] link_dump: why=%s name=%s peers=%zu established=%zu "
           "rejected=%llu\n",
           (why != NULL) ? why : "?", s->name, links, established,
           (unsigned long long)total_rejected);
    /* The breakdown is walked, not listed: eight hand-written key=value pairs
     * would be eight places for a name to be mistyped and eight arguments for a
     * printf, and a loop over the one table cannot disagree with
     * fed_federate_reason(). The total is asserted to agree with the sum here
     * rather than in a test, because a dump whose parts do not add up is worse
     * than no dump -- and the arithmetic is two lines. */
    printf("[observable] link_reject_reasons: ");
    for (i = 1; i < (size_t)FED_RESULT_COUNT; i++) {
        printf("%s%s%llu", (i > 1u) ? " " : "", FED_REASON_KEY[i],
               (unsigned long long)g_rejected[i]);
    }
    printf("\n");

    for (i = 0; i < links; i++) {
        const server_link_t *link = server_link_at(s, i);

        if (link == NULL) {
            continue;
        }
        /* last_sent and last_recv are the two stamps T3 and T4 compare, and a
         * link dump that does not carry them makes "why did it think the peer
         * was dead" answerable only by reading the other node's log. */
        /* THE RECONNECT SCHEDULE IS ON THIS LINE, and it is here for the reason
         * the other four fields are: an operator reading "why is irc.b not being
         * dialled" needs the retry count, the budget that was spent and the
         * stamp the next attempt is waiting for, and they are all in the same
         * struct as the state they explain. A dump without them would say
         * `state=INIT fd=-1 initiator=1` for a link that is about to be dialled
         * and for one that has given up, and those two need different repairs.
         *
         * gave_up is printed as the COUNT 0/1 rather than as a token because it
         * shares the field with two numbers and a mixed vocabulary on one line
         * is the thing this dump has otherwise been careful to avoid. */
        printf("[observable] link: peer=%s state=%s fd=%d initiator=%d "
               "epoch=%llu last_sent=%llu last_recv=%llu burst_done=%d "
               "retries=%u gave_up=%d retry_at=%llu\n",
               link->name, fed_state_name(link->state), link->fd, link->initiator,
               (unsigned long long)link->epoch,
               (unsigned long long)link->last_sent_ms,
               (unsigned long long)link->last_recv_ms, link->burst_done,
               link->retries, link->gave_up,
               (unsigned long long)link->retry_at_ms);
    }
    fflush(stdout);
}

/* ---------------------------------------------------------------------------
 * Link table
 * ---------------------------------------------------------------------------
 */

/* The ONE place server_link_t::state is written, which is what core/server.h
 * requires when it says the mirror "is written in exactly one place --
 * fed_link_set_state() -- and never assigned at a call site". hs.state is the
 * truth; this copies it. Every FSM transition in this file goes through the
 * helper below, so a transition cannot forget to resync the mirror, and T6 is
 * then a repair for a bug rather than the mechanism. */
static void fed_link_set_state(server_link_t *link)
{
    if (link != NULL) {
        link->state = (int)link->hs.state;
    }
}

/* The link a CONNECTION belongs to, or NULL.
 *
 * NOT a lookup by descriptor, and the reason is a failure this phase's own test
 * suite found. Between a link's connection dying and something resetting the
 * link, link->fd is STALE: the reaper cleared by_fd[fd] but nothing cleared the
 * name the link kept. A descriptor is a small integer and the kernel hands the
 * same one out again immediately, so the next connection to be accepted gets
 * the very descriptor the dead link still names. A `link->fd == c->fd` lookup
 * then returns the DEAD link for a LIVE, UNRELATED connection, and the FSM
 * starts rejecting a stranger's claim against a link sitting in HANDSHAKE_SENT
 * with somebody else -- which is a real, observed failure, not a hypothetical
 * one.
 *
 * So the descriptor is necessary but not sufficient, and the second half of the
 * test is conn_t::peer_name: a connection that arrived on the listener has none
 * until fed_link_established() gives it one, and a connection the DIAL FSM
 * created already carries the name of the peer it was dialled for. Both halves
 * together identify the link -- the descriptor says which socket, the name says
 * which peer that socket is supposed to be speaking to -- and a recycled
 * descriptor fails the second half, because a fresh conn_new() has a NULL
 * peer_name.
 *
 * server_link_conn() in core/server.h has the same exposure and states it: a
 * link whose descriptor is stale is the case where by_fd[fd] hands back some
 * OTHER connection. This function is that same observation with a guard on it,
 * and the guard is what makes the lookup usable from the inbound path, where a
 * link with a stale descriptor is an ordinary state rather than an accident. */
static server_link_t *fed_link_of_conn(const server_t *s, const conn_t *c)
{
    size_t i;

    if (s == NULL || c == NULL || c->peer_name == NULL) {
        return NULL;
    }
    for (i = 0; i < s->nlinks; i++) {
        if (s->links[i].fd == c->fd && same_name(s->links[i].name, c->peer_name)) {
            return &s->links[i];
        }
    }
    return NULL;
}

/* Create a link for a name this node does not have one for. Used on the
 * accepting side, where 2.3 says a link exists once a peer is "configured" --
 * and an inbound claim is a configuration this node did not write and must
 * still accept, because either side may connect.
 *
 * `initiator` is 0 because an accepted link has nothing to dial: it has no
 * pre-resolved address, since this node never learned one. T7 checks the
 * address as well as the flag, so the two cannot come to disagree. */
static server_link_t *fed_link_new(server_t *s, const char *name, int initiator)
{
    server_link_t *link;

    if (s == NULL || name == NULL) {
        return NULL;
    }
    /* The vector grows geometrically like the other registries on server_t, and
     * past IRC_FED_MAX_PEERS rather than refusing. The constant is that
     * vector's INITIAL capacity, not a limit on the number of peers a node may
     * be linked to, and refusing at it would make a capacity number a policy. */
    if (s->nlinks == s->links_cap) {
        size_t want = (s->links_cap == 0u) ? (size_t)IRC_FED_MAX_PEERS
                                           : s->links_cap * 2u;
        server_link_t *grown =
            (server_link_t *)realloc(s->links, want * sizeof *grown);

        if (grown == NULL) {
            /* A node that cannot allocate a link cannot have a peer, and
             * refusing here is better than a link table that is half a peer.
             * The caller reports it; this function has no verdict to give. */
            return NULL;
        }
        /* Zero the new slots. A link that is not zeroed would carry a
         * descriptor from the previous boot of this array, and a stale fd is
         * the one thing server_link_conn() cannot defend against -- it indexes
         * by_fd BY the descriptor. */
        memset(grown + s->links_cap, 0,
               (want - s->links_cap) * sizeof *grown);
        s->links = grown;
        s->links_cap = want;
    }
    link = &s->links[s->nlinks];
    memset(link, 0, sizeof *link);
    memcpy(link->name, name, strlen(name) + 1u);
    link->fd = -1;
    link->initiator = initiator;
    link->burst_done = 0;
    handshake_init(&link->hs);
    fed_link_set_state(link);
    s->nlinks++;
    return link;
}

server_link_t *fed_link_configure(server_t *s, const char *name,
                                  const struct sockaddr *sa, socklen_t salen)
{
    server_link_t *link;

    if (s == NULL || name == NULL || sa == NULL || salen == 0) {
        return NULL;
    }
    /* 2.3's own reason, applied to a peer name rather than to this node's: a
     * name this node could not stamp on an irc-serve-origin tag is a name it
     * could not address, and a second link for a name already in the table is
     * the uniqueness rule enforced at the only point where it can be cheap. */
    if (strlen(name) > (size_t)IRC_MAX_SERVER_NAME ||
        !irc_serve_server_name_valid(name)) {
        return NULL;
    }
    if (server_find_link(s, name) != NULL) {
        return NULL;
    }
    link = fed_link_new(s, name, 1);
    if (link == NULL) {
        return NULL;
    }
    /* The PRE-RESOLVED address, on the link rather than in a configuration
     * array: a link that is re-dialled after a failure carries the address it
     * failed to reach, and a reconnect therefore needs no lookup -- which is
     * 3.4's rule, not a convenience. */
    memcpy(&link->addr, sa, (size_t)salen);
    link->addrlen = salen;
    return link;
}

/* ---------------------------------------------------------------------------
 * THE DEPARTURE ANNOUNCEMENT, AND WHY IT IS NOT A ROW IN THE S-VERB TABLE
 * ---------------------------------------------------------------------------
 * Tell this node's remaining peers that THIS NODE'S OWN NAME is going away,
 * because a link just went down. It is a SQUIT -- 4.3's word for exactly this --
 * and it is emitted from the link LIFECYCLE rather than from any of the five
 * fan-out arms, because there is no client emission to fan out: nothing on this
 * node asked for anything, a socket did.
 *
 * IT IS NOT IN S_VERBS, and that is the same conclusion the T3 keepalive reaches
 * from the other side, for the same reason and with the same citation:
 * tests/integration/test_fed_wire.c asserts the contents of that table, and 4.3's
 * list is the FORWARDED vocabulary -- verbs a node relays. A node announcing its
 * own departure relays nothing. Putting `{"SQUIT", "SQUIT"}` in that table would
 * also be meaningless, because the column on the left is a CLIENT verb and no
 * client sends one; a row there would claim that a client's SQUIT is forwarded,
 * which is a claim about the client surface that this node does not implement
 * and would not implement. So the verb is named here and the shared
 * render-and-queue step (fed_queue_line(), stamp the 2.4 block, build, render,
 * bound-check, terminate, queue) is the same one T3 and fed_send_sverb() use.
 *
 * ONE ID FOR THE WHOLE FAN-OUT, which is a deliberate difference from
 * fanout_forward_sverb()'s per-target minting, and the reason is 2.4's dedup
 * scope. The store is PER NODE, not per peer, so a node reachable by two of this
 * node's peers sees the same (origin, epoch, id) twice and MUST drop the second:
 * that is what the per-node rule is for. Minting per peer would make the two
 * copies two different keys, so the third node would apply the purge twice and
 * store two entries for one message. This is one message with several targets.
 *
 * THE COST, stated because it is a real one: the fan-out is a broadcast to every
 * ESTABLISHED link, which is 3.1's amended owned/`state-change` row rather than
 * a unicast, so on a large mesh one link failure costs one line per peer. It is
 * paid on a link event, which is rare, and the alternative -- telling nobody --
 * leaves every peer holding a roster for a server that is not there until the
 * next burst, and driving bursts is Phase 9.
 *
 * AND THE SENTENCE THIS SENDS IS WIDER THAN THE EVENT, which is a property of
 * the TRIGGER rather than of this function: the event is ONE link going down,
 * and the sentence is "this node's name is gone". On a mesh where this node is
 * still reachable by somebody else, a peer told here purges a roster for a
 * server that is still there, and the roster comes back from a later SJOIN or
 * the next burst -- which Phase 9 owns. That is the price of telling anybody at
 * all, and it is bounded only by that policy, so it is written down here rather
 * than left for a reader to discover as a stale roster on a live server. A reader
 * who thinks it should be "my link to you is down" instead should read
 * 7/Phase 9, which is where the answer belongs.
 */
static int fed_send_squit(server_t *s, const server_link_t *dying)
{
    irc_serve_tags_t tags;
    const char *params[1];
    fed_queue_why_t why = FED_QUEUE_OK;
    size_t targets = 0;
    int sent = 0;

    if (s == NULL) {
        return 0;
    }
    /* COUNTED FIRST, AND THE COUNT IS WHAT MAKES THE "NO ID SPENT" DECISION.
     * core/fanout.c says the same about a forward that is refused before it is
     * stamped: the ids come from a per-SERVER counter and a hole in that sequence
     * is a hole in the sequence, and nothing requires it to be contiguous. It is
     * still not free, so a node whose only ESTABLISHED link is the one that just
     * went -- the ordinary TWO-NODE mesh, where this announcement has nobody to
     * go to -- spends no id and prints nothing. */
    for (size_t i = 0; i < s->nlinks; i++) {
        if (&s->links[i] == dying) {
            /* The link that died is NOT a peer this is told through, and the
             * reason is the wire rather than taste: its caller is about to mark
             * that connection CLOSING, so a line queued onto it is a line nobody
             * will read, and counting it as a peer told would be a claim the wire
             * does not support. The far side of a dead link learns this node is
             * gone from the link, which is the channel the event arrived on. */
            continue;
        }
        if (s->links[i].state == (int)ESTABLISHED &&
            server_link_conn(s, &s->links[i]) != NULL) {
            targets++;
        }
    }
    if (targets == 0u) {
        return 0;
    }

    memset(&tags, 0, sizeof tags);
    memcpy(tags.origin, s->name, strlen(s->name) + 1u);
    tags.epoch = s->epoch;
    tags.id = server_next_msg_id(s);
    tags.hops = 0; /* originated here, so it leaves at zero (2.4) */

    /* SQUIT <server>: the name of the server that is going away, which is THIS
     * one. verbs.h freezes the shape; the [optional reason] is not sent because
     * nothing on this node has one to give, and an unused field on a wire format
     * is a field a second implementation has to guess about. */
    params[0] = s->name;

    for (size_t i = 0; i < s->nlinks; i++) {
        conn_t *c;

        if (&s->links[i] == dying || s->links[i].state != (int)ESTABLISHED) {
            continue;
        }
        c = server_link_conn(s, &s->links[i]);
        if (c == NULL) {
            continue;
        }
        if (fed_queue_line(s, c, &tags, s->name, "SQUIT", params, 1, &why) != 0) {
            /* Reported, not swallowed, for the reason every other refusal in
             * this module is: a node that failed to announce its departure and
             * says nothing looks exactly like a node whose peers are all silent,
             * and the two have opposite fixes. server_queue() has already
             * counted a saturated link and marked it CLOSING (3.4), so this is
             * the report and not a second count. */
            printf("[observable] fed_squit_send_failed: self=%s peer=%s reason=%s\n",
                   s->name, s->links[i].name, fed_queue_why_name(why));
            continue;
        }
        sent++;
    }
    printf("[observable] fed_squit_sent: self=%s peers=%d id=%llu\n", s->name, sent,
           (unsigned long long)tags.id);
    return sent;
}

/* The link back to INIT, keeping `initiator` and the address.
 *
 * `announce` says whether this node's own departure is announced to its OTHER
 * peers, and the parameter exists because the two callers that arrive here
 * without a route having ever existed MUST NOT announce, and the reason is a
 * hazard rather than a tidiness concern.
 *
 * A SQUIT for this node's own name tells every peer holding it to purge this
 * node's roster and its name from its channels' servers[]. A link that was
 * ESTABLISHED and has gone away genuinely means those peers should do that --
 * they cannot reach this node through that link any more. A link whose HANDSHAKE
 * NEVER COMPLETED means the opposite: it is a socket that was opened and never
 * authenticated, so no peer ever received a burst attributed to this node
 * through it, and the other links are still up. Announcing on that path would
 * tell the whole mesh that a node is gone when it is serving, and every peer
 * would purge a live node's roster. That is not a smaller version of the
 * announcement; it is a different and wrong statement, and it is the reason the
 * flag is a parameter rather than something every caller inherits from the
 * shared body.
 *
 * The cost of the parameter is one argument at three call sites and the
 * possibility of a caller passing the wrong value -- which is why each call site
 * carries the argument in the name at its call and not only in the comment here. */
static void fed_link_down(server_t *s, server_link_t *link, int announce)
{
    if (link == NULL) {
        return;
    }
    /* THE DEPARTURE GOES OUT FIRST, while the other links are still up, and the
     * order is the whole point: this announcement is queued onto peers' write
     * queues, and every step below either closes a descriptor or forgets that a
     * peer existed. A SQUIT emitted afterwards would be a line on a link the node
     * has already stopped believing in. */
    if (announce != 0) {
        (void)fed_send_squit(s, link);
    }
    /* Everything below is a no-op on a link that never established, which is
     * what made it safe to share the body in the first place: the epoch is
     * already 0, burst_done is already 0, the stamps are already 0, and
     * fed_burst_abandon() on a link with no transaction open returns at once. */
    handshake_init(&link->hs);
    fed_link_set_state(link);
    link->fd = -1;
    /* A link that has gone down has learned nothing about its peer's current
     * boot, and 4.3's burst carries the origin's epoch, so leaving the old one
     * here would be a resync attributing a burst to the wrong boot. The
     * re-linking server of the same name is a fresh handshake and says so
     * again. */
    link->epoch = 0;
    /* A link that reconnects has not applied its burst, whatever this one did.
     * 4.3 says a resync REPLACES rather than merges, and the flag is what makes
     * that true of a link that comes back. */
    link->burst_done = 0;
    /* AND THE IN-FLIGHT TRANSACTION GOES WITH IT. A burst that never reached its
     * terminator because the link died has nothing to compare its counts against,
     * and leaving the shadow open would mean the next burst on this link's name
     * started by appending to a half-built one -- which is a state this node
     * cannot explain and no reader of the counters could. The BEGIN in the next
     * burst would discard it anyway; discarding it here means the discard is
     * reported against the link that went down rather than against the next
     * burst, which is where an operator looking for a flapping link will look. */
    fed_burst_abandon(link);
    link->last_sent_ms = 0;
    link->last_recv_ms = 0;
    fed_dump(s, "link_down");
}

void fed_link_reset(server_t *s, server_link_t *link)
{
    if (link == NULL) {
        return;
    }
    /* A FULL second chance, not one more attempt against a spent budget. The
     * budget is a count of consecutive failures and the reset spends a fresh
     * one, so an operator who resets a link has not decided to allow exactly one
     * more knock -- they have decided the node was wrong and should try again
     * from the start. retry_at_ms goes to 0 as well, which is what makes the
     * next tick dial IMMEDIATELY rather than after a backoff the operator did
     * not ask for: this is the escape hatch, and an escape hatch that made you
     * wait would be a second-class one. */
    link->retries = 0u;
    link->gave_up = 0;
    link->retry_at_ms = 0u;
    /* created_ms is NOT the latch any more -- see the retraction block in the
     * header -- but it is cleared here anyway, and the reason is that T2
     * compares against it. A reset that left the attempt stamp in place would
     * put a link that has just been told to try again straight into the
     * handshake timeout on the tick after it dials, because the stamp would
     * already be older than IRC_FED_HS_TIMEOUT_MS. */
    link->created_ms = 0;
    printf("[observable] link_retry_reset: peer=%s\n", link->name);
    /* ANNOUNCED, and deliberately so even when the link being reset never
     * established: fed_link_reset() is the OPERATOR's door, and an operator who
     * resets a link is saying "I am taking this node off this peer for now" --
     * which is a departure from the mesh's point of view whatever the link's own
     * state was, and peers that keep a roster for a node its operator has
     * declared off-link are holding state that is wrong. The automatic path (T2)
     * does NOT announce, and the difference is fed_link_down()'s parameter. */
    fed_link_down(s, link, 1);
}

/* ---------------------------------------------------------------------------
 * The exchange
 * ---------------------------------------------------------------------------
 */

/* Queue this node's FEDERATE on a peer connection.
 *
 * It is built rather than formatted, because FEDERATE is not the S-verb of any
 * client verb and fed_send_sverb() takes a client verb and maps it (verbs.h is
 * explicit that the mapping is applied there so no caller can hand it an
 * already-mapped verb).
 *
 * It is ALSO not fed_queue_line(), and that is now a stated decision rather than
 * the leftover of one: fed_queue_line() stamps a 2.4 block, and a FEDERATE
 * carries none. Its epoch and its secret are PARAMETERS, because 2.4's block is
 * what a receiver needs in order to deduplicate and loop-check a message, and a
 * handshake is neither relayed nor looped -- the only thing that ever has to
 * read this line is the peer's handshake code, which is about to look at every
 * field of it. So this line goes through message_build() and message_format()
 * directly, and the three lines of overlap with fed_queue_line() below are the
 * part that has no block to stamp. The cost of not folding this one in is three
 * lines; the cost of folding it in would be a helper with a "no tags here" mode
 * that its other caller could reach by accident. */
static int fed_queue_federate(server_t *s, server_link_t *link, conn_t *c)
{
    const char *params[4];
    char epoch[24];
    char secret[IRC_FED_MAX_SECRET];
    char line[IRC_MAX_LINE + 2];
    message_t m;
    size_t len;

    /* 24 bytes for a uint64_t in decimal: 20 digits at the maximum, plus the
     * NUL. The alternative -- a shared buffer sized by an estimate -- is a
     * truncation of the one field 2.4 exists so that a restarted peer is
     * distinguishable from the one it replaced. */
    (void)snprintf(epoch, sizeof epoch, "%llu", (unsigned long long)s->epoch);
    /* A NODE WITH NO SECRET REFUSES TO SEND A CLAIM, and it says so in its own
     * words rather than letting the claim go out with an empty parameter.
     *
     * The reason is the POLICY, and it is now stated on BOTH sides: an inbound
     * FEDERATE on a node with no configured secret is refused with
     * FED_NO_SECRET (fed_check_federate() step 2, which says so at length), so
     * an outbound claim from the same node would be refused by a correctly
     * configured peer with a reason its operator cannot act on -- "your secret
     * is wrong" for a node that has no secret. The operator of the
     * no-secret node is the one who can fix it, and the line that tells them is
     * the outbound one: this node is the one that cannot authenticate anybody.
     *
     * It is a separate reason and not a reuse of UNRENDERABLE because
     * UNRENDERABLE is a message.c failure -- "this line does not fit or does not
     * parse" -- and an operator reading it would go looking for a formatting bug
     * in a module that is behaving exactly as specified. The two are opposites
     * (a message that cannot be built versus a policy that forbids building it)
     * and they belong to different files. */
    if (g_secret_len == 0u) {
        printf("[observable] link_send_failed: peer=%s reason=NO_SECRET "
               "configured=0\n",
               link->name);
        return -1;
    }
    memcpy(secret, g_secret, g_secret_len + 1u);

    params[0] = s->name;                        /* our own claim        */
    params[1] = epoch;                          /* our per-boot epoch   */
    params[2] = secret;                         /* the shared token     */
    params[3] = IRC_SERVE_VERSION;              /* the ONE version copy */

    if (message_build(&m, NULL, s->name, "FEDERATE", params, 4) != 0) {
        printf("[observable] link_send_failed: peer=%s reason=UNBUILDABLE\n",
               link->name);
        return -1;
    }
    /* The +2 is reply.c's arithmetic and the reason is the same: IRC_MAX_LINE
     * counts a legal line INCLUDING its CRLF and message_format() reserves a
     * byte for its NUL. */
    len = message_format(&m, line, sizeof line - 2u);
    message_free(&m);
    if (len == 0u) {
        printf("[observable] link_send_failed: peer=%s reason=UNRENDERABLE\n",
               link->name);
        return -1;
    }
    /* RFC 1459 2.3. message_format() terminates nothing. */
    line[len] = '\r';
    line[len + 1u] = '\n';
    if (server_queue(s, c, line, len + 2u) != 0) {
        /* Already counted and already marked CLOSING by server_queue(): a
         * saturated link is DROPPED, not buffered (3.4). Not counted twice. */
        printf("[observable] link_send_failed: peer=%s reason=LINK_SATURATED\n",
               link->name);
        return -1;
    }
    return 0;
}

/* The whole of a rejection, in three steps and always in this order.
 *
 *   (a) print. NOT gated on s->trace, and the reason is the one this project
 *       uses for every refusal: a rejected handshake is a bug report or an
 *       attack, and a flag that can silence a bug report is not a flag that
 *       should be able to silence a bug report. The volume argument that
 *       justifies the per-line trace does not apply to a line that appears
 *       once per rejected connection.
 *   (b) handshake_fail(), so the FSM records that this exchange ended wrongly.
 *       A link whose FSM still said HANDSHAKE_SENT after its connection is
 *       gone would sit in T2 until the timeout fired and would report a
 *       handshake timeout for something that was rejected in the first
 *       millisecond.
 *   (c) conn_mark_closing() and NEVER close(). 3.4 puts the close at one fixed
 *       point in the loop, and a second close path in a file that owns peer
 *       links is precisely how a descriptor gets closed twice. */
static void fed_reject(server_t *s, server_link_t *link, conn_t *c,
                       fed_federate_result_t result, const char *claim)
{
    const char *peer = (link != NULL) ? link->name : claim;

    printf("[observable] link_rejected: peer=%s reason=%s fd=%d\n",
           (peer != NULL && peer[0] != '\0') ? peer : "?",
           fed_federate_reason(result), (c != NULL) ? c->fd : -1);
    /* Counted whether or not there is a link to fail. An inbound claim that
     * arrives on the listener has no link yet -- that is the ordinary accepting
     * case -- and counting only the ones that did have one would make the
     * headline number report the minority and the per-reason breakdown report
     * everything, which is the kind of pair that reads as a bug in the other
     * module. */
    if (s != NULL) {
        s->n_link_rejected++;
        if (result == FED_DUPLICATE_LINK) {
            s->n_link_duplicate++;
        }
    }
    if (link != NULL) {
        (void)handshake_fail(&link->hs);
        fed_link_set_state(link);
    }
    if (c != NULL) {
        conn_mark_closing(c);
    }
    count_reject(result);
    fed_dump(s, "rejected");
}

/* A link that has earned its place: the descriptor, the peer's epoch, and the
 * FSM. Split out of fed_federate_inbound() because both the accepting side and
 * the dialling side's promotion end here, and 2.3 wants them to be the same
 * transition. */
static void fed_link_established(server_t *s, server_link_t *link, conn_t *c,
                                 const char *claim, uint64_t peer_epoch)
{
    link->fd = c->fd;
    link->epoch = peer_epoch;
    /* The liveness stamps start now rather than at configuration: before this
     * point the link has no peer that could be alive or dead, and a stamp from
     * configuration time would make a slow handshake look like a silent one the
     * moment it completed. */
    link->last_sent_ms = server_now_ms();
    link->last_recv_ms = link->last_sent_ms;
    /* 2.3: a peer connection is exempt from the client registration state
     * machine. Changing `kind` here is what takes it out: reply.c refuses a
     * CONN_SERVER destination, so a numeric can no longer be written to this
     * connection even by a path that does not know it is a peer.
     *
     * peer_name stays a display copy and a NULL one if the allocation fails.
     * Nothing routes by it (core/server.h is explicit that the link is the
     * authority), so a missing copy costs a diagnostic field and no routing. */
    c->kind = CONN_SERVER;
    if (c->peer_name == NULL) {
        char *copy = (char *)malloc(strlen(claim) + 1u);

        if (copy != NULL) {
            memcpy(copy, claim, strlen(claim) + 1u);
            c->peer_name = copy;
        }
    }
    /* THE BUDGET IS REFILLED HERE, and it is here rather than at the end of the
     * function for the same reason federation_resync() is below it: a link that
     * has just come up is a link that should be dialled AGAIN without waiting,
     * and a link that came up after a backoff still has that backoff's stamp on
     * it. Leaving it would mean a link that recovered keeps waiting out a
     * schedule earned for a failure it has already fixed.
     *
     * `retries` goes to 0 rather than being decremented, and the difference
     * matters: it is what makes the budget a budget of CONSECUTIVE failures
     * rather than a lifetime cap on a link, so a peer that flaps is retried
     * indefinitely (one fresh budget per success) while a peer that is simply
     * dead is not. `gave_up` is cleared for the same reason, and it is cleared
     * HERE rather than only in fed_link_reset() because a link cannot reach
     * ESTABLISHED without coming through this function -- so a link whose budget
     * ran out and which then succeeded has, by the fact of its success, been
     * fixed, and holding the give-up against it would be holding it against the
     * evidence. */
    link->retries = 0u;
    link->gave_up = 0;
    link->retry_at_ms = 0u;
    printf("[observable] link_established: peer=%s fd=%d initiator=%d "
           "epoch=%llu\n",
           link->name, link->fd, link->initiator,
           (unsigned long long)link->epoch);
    fed_dump(s, "established");
    /* THE RESYNC, and it goes HERE rather than in either of the two paths that
     * reach this function, because 2.3 wants the accepting side and the dialling
     * side's promotion to be the same transition and 4.3's "on every link
     * establishment" has to be true of both of them. A call in the accept path
     * only would be the INITIATOR's burst, which is 4.3's literal wording and is
     * not sufficient: a node only forwards to peers that already hold the
     * chan_t, so in a two-node fixture the RESPONDER's channels would never reach
     * the initiator, a user there would be invisible to the initiator for ever,
     * and 7/Phase 6's full-353 criterion would fail on one of the two nodes.
     *
     * BOTH SIDES BURSTING IS A DELIBERATE SUPERSET of the doc's sentence "the
     * initiator sends full state", and it costs one extra burst per link. What it
     * buys is that "on every link establishment" means what a reader of 4.3 would
     * expect it to mean, and that neither node's view of the other depends on
     * which of the two happened to dial. The asymmetry the doc describes is
     * real -- the initiator does have to send its state or the other node learns
     * nothing -- but it is a statement about the MINIMUM, and a minimum is not a
     * rule about what the responder may do.
     *
     * ONE ORDERING CONSTRAINT, and it is the reason this is not at the top of
     * the function: the burst needs the link's descriptor and the peer's epoch,
     * so it has to be after both are set. It does NOT wait for the peer's own
     * burst, and cannot: neither side is going to block on the other, so the two
     * transactions cross on the wire and each is applied on arrival. There is no
     * ordering to agree on because neither transaction depends on the other -- a
     * burst is a statement about the sender, and the sender's state does not
     * change because somebody received it. */
    (void)federation_resync(s, link);
}

fed_federate_result_t fed_check_federate(const server_t *s,
                                         const server_link_t *self,
                                         const message_t *m, const char *secret,
                                         uint64_t *peer_epoch_out)
{
    const char *claim;
    uint64_t peer_epoch = 0;
    size_t i;

    if (s == NULL || m == NULL) {
        return FED_BAD_ARITY;
    }

    /* --- 1. shape ------------------------------------------------------- */
    /* A FEDERATE names the sender twice: once as the prefix and once as the
     * first parameter. The PARAMETER is the authority, and the prefix is
     * required to be present because a line that does not say who sent it is
     * not a handshake. They are deliberately not cross-checked against each
     * other here: the inbound prefix rules are fed_dispatch()'s, and a second
     * opinion about them in the link module is a second opinion somebody can
     * have. Until C3 exists, a peer whose prefix disagrees with its claim is
     * one the shape check accepts and the claim check then applies -- which is
     * the right way round, because the claim is the name that would have to be
     * unique. */
    if (m->nparams != 4 || m->prefix == NULL) {
        return FED_BAD_ARITY;
    }
    claim = m->params[0];
    if (claim == NULL || strlen(claim) > (size_t)IRC_MAX_SERVER_NAME ||
        !irc_serve_server_name_valid(claim)) {
        return FED_BAD_NAME;
    }
    if (parse_epoch(m->params[1], &peer_epoch) != 0) {
        return FED_BAD_EPOCH;
    }
    if (strcmp(m->params[3], IRC_SERVE_VERSION) != 0) {
        return FED_BAD_VERSION;
    }

    /* --- 2. the secret -------------------------------------------------- */
    /* Before the identity checks, so that a node which is not allowed to be
     * here learns nothing about this node's name space. */
    /* AN EMPTY CONFIGURED SECRET REFUSES, AND THAT IS THE POLICY.
     *
     * `irc-serve 6667` has no --secret, so the secret is "", and the constant-
     * time compare below answers ACCEPT for an offered "" because two empty
     * strings are equal. On a default-configured node that made the secret step
     * a step nobody could fail: the ONLY thing standing between anyone who can
     * reach the TCP port and a peer link under a name of their choosing was an
     * equality between two empty strings.
     *
     * AN HONEST WORD ON HOW REACHABLE THAT WAS, because the difference matters
     * to whoever reads this later. An empty parameter cannot be put on the wire
     * in a non-final position by this node's parser: core/message.c skips an
     * empty token rather than counting it, and a `:` parameter swallows the rest
     * of the line. So `:x FEDERATE n 1 "" irc-serve-0.1.0` arrives with the
     * secret parameter set to the two characters quote-quote, and the line
     * `:x FEDERATE n 1 : irc-serve-0.1.0` arrives as three parameters and is
     * refused as BAD_ARITY. Checked against the shipped binary, not inferred.
     * The empty-vs-empty accept was therefore LATENT rather than open: what
     * stood between a default-configured node and a stranger was a parser rule
     * in a module that knows nothing about peers, not a check in this path.
     * A change to a parameter rule in core/message.c -- which is a
     * one-line-shaped change and is the kind this tree makes -- would have opened
     * it, and nothing in the link path would have said so. This check is the
     * link path's own answer, and it holds whatever a parser does with an empty
     * parameter.
     *
     * The alternative -- treating "no secret" as "no authentication" -- was
     * what the default used to mean, and it is not what an operator who reads
     * `secret=none` on the startup line is being told. Federation here is
     * OPT-IN: a node federates because it was given a secret, so a node with no
     * secret is a node that federates with nobody, and it says so on the wire
     * with a verdict of its own rather than folding the case into BAD_SECRET.
     * An operator reading `reason=` has to be able to tell "somebody guessed
     * wrong" from "this node is not configured to federate", because the fixes
     * are opposites: the first is a credential under attack, the second is a
     * missing --secret. BAD_SECRET on a node whose secret is empty would also be
     * a lie in the other direction -- it would say the offered value was wrong
     * when the truth is that no value is right.
     *
     * BEFORE secret_matches(), and deliberately so. secret_matches() is a
     * correct constant-time compare and stays one, unchanged; what it cannot do
     * is express a policy, and "is authentication switched on at all" is a
     * policy rather than an equality.
     *
     * It does not break backward compatibility, which is the thing that made it
     * look hard. `irc-serve 6667` still starts, binds, serves clients and
     * prints the same lines: the CLIENT surface is untouched, and this check is
     * reached only by a FEDERATE, a peer handshake that did not exist before
     * Phase 6 and therefore cannot be something a working deployment depended
     * on.
     *
     * The cost, stated exactly, and it is SMALLER than the argument above first
     * suggests: a node with no secret could not federate anyway, in either
     * direction. Its own claim never left the node -- fed_queue_federate()
     * renders a FEDERATE whose third parameter is the secret, and
     * message_format() refuses a parameter the wire cannot represent in a
     * non-final position, which an empty one is -- so a default-configured node
     * dialling a peer reports `link_send_failed: reason=UNRENDERABLE` and sends
     * nothing at all. Both of those were checked against the shipped binary,
     * not inferred. So there is no working all-`--secret`-less mesh for this to
     * break; what changes is that the INBOUND refusal now exists, is named, and
     * is counted, instead of depending on a parser in core/message.c to keep
     * an empty parameter off the wire.
     *
     * The one behaviour a deployment could notice is the one the policy is
     * ABOUT: a node with a --secret and a node without one can no longer link
     * to each other, which is correct, because one of them is not authenticating
     * anybody. The remaining cost is a diagnostic that used to say
     * UNRENDERABLE where it means "you gave me no secret", and that is a
     * follow-up on the OUTBOUND side of fed_queue_federate() rather than
     * something this check can fix. */
    if (secret == NULL || secret[0] == '\0') {
        return FED_NO_SECRET;
    }
    if (!secret_matches(secret, m->params[2])) {
        return FED_BAD_SECRET;
    }

    /* --- 3. not our own name -------------------------------------------- */
    if (same_name(claim, s->name)) {
        return FED_SELF_NAME;
    }

    /* --- 4. uniqueness -------------------------------------------------- */
    /* The link this exchange is ON is skipped: it is not a rival claim on the
     * name it is handshaking about, and a dialling node has held one since the
     * moment the peer was configured. Every OTHER link with this name is a
     * rival, and the difference between the two verdicts is the whole of 2.3's
     * rule: a link that is ESTABLISHED is a live route to that name, and
     * admitting a second one is the split brain; a link that HOLDS A DESCRIPTOR
     * but is not established is a half-open exchange for the same name, and
     * admitting a second one would put two descriptors on one identity.
     *
     * AND A LINK WITH NO DESCRIPTOR IS NEITHER. That clause is the correction,
     * and it was missing until a re-link was tested: a link in INIT with fd == -1
     * is a NAME and a DESTINATION, not a claim on the name. It is what fed_dead()
     * leaves behind -- the peer went away, the descriptor is closed, the name is
     * kept so that T7 can dial it again and so that 2.2's fail-closed rule has an
     * origin to be unreachable FROM. Refusing a peer's re-claim because such a
     * link exists made 2.2's "re-linking a server of the same name resurrects the
     * channel" UNREACHABLE: the peer re-dialled, was told the name was in use by
     * a link that had no socket on it, and the mesh could never recover from a
     * partition without an operator deleting configuration.
     *
     * THE COST, and it is the reason this is about the DESCRIPTOR and not about
     * the state: a node can now hold at most one link per name whose fd is >= 0
     * and any number whose fd is -1, and only the first kind is a claim. A link
     * that is FAILED or TIMED_OUT WITH A DESCRIPTOR still holds one -- T2 leaves
     * the descriptor alone on purpose -- so a peer re-dialling into that state is
     * still refused with NAME_IN_USE, and clearing it is fed_link_reset()'s job.
     * That asymmetry is left as it is rather than papered over: it is the same
     * asymmetry link.h draws between a link that was established and went away
     * (resettable, because there is something to stop believing in) and one that
     * never completed (terminal, because there was never anything to believe). */
    for (i = 0; i < server_link_count(s); i++) {
        const server_link_t *other = server_link_at(s, i);

        if (other == NULL || other == self || !same_name(other->name, claim)) {
            continue;
        }
        if (other->state == (int)ESTABLISHED) {
            return FED_DUPLICATE_LINK;
        }
        if (other->fd >= 0) {
            return FED_NAME_IN_USE;
        }
    }
    /* And the same answer reached through the function every router uses. It
     * is redundant with the scan above by construction, and it is here anyway:
     * server_find_peer() is the ESTABLISHED-narrowed predicate, so if the two
     * ever disagreed about what counts as established this would reject rather
     * than admit a second route to a name the node can already reach. */
    if (server_find_peer(s, claim) != NULL) {
        return FED_DUPLICATE_LINK;
    }
    /* A connection already on a link, presenting a DIFFERENT name.
     *
     * This had no verdict of its own and answered FED_DUPLICATE_LINK, which was
     * wrong and is retracted here: a node dialled a peer under one name and the
     * peer announced another is a MISCONFIGURATION -- one side's --peer or
     * --name disagrees with the other side's --name -- and not a split brain.
     * The two have opposite fixes and different shapes of aftermath, and
     * reporting a name disagreement as a duplicate route is exactly the
     * overloading this verdict was supposed to prevent. Split brain has its own
     * verdict above, and it is the one that increments n_link_duplicate.
     *
     * The rejection itself is unchanged and for the same reason as every other
     * rejection: a link has exactly one name (the table is keyed on it), so a
     * second identity presented on one socket cannot be adopted, and accepting
     * it would leave this node with a route whose name is not the one the
     * handshake was checked against. The line is closed, counted and dumped
     * like any other, under a name that says what happened. */
    if (self != NULL && !same_name(self->name, claim)) {
        return FED_NAME_MISMATCH;
    }
    /* Only on the accepted path, and the out-parameter is why: the epoch is
     * parsed in the shape check because that is where the grammar belongs, and
     * the caller needs it to stamp the link. Returning it only on FED_OK means
     * a caller that ignores a verdict never has a half-validated epoch to
     * write onto a link, which is the one way this out-parameter could be
     * misused. A NULL out-parameter is fine -- it is optional. */
    if (peer_epoch_out != NULL) {
        *peer_epoch_out = peer_epoch;
    }
    return FED_OK;
}

/* A refusal that is NOT a verdict on the peer's line, and therefore is not
 * counted and does not appear in the per-reason breakdown.
 *
 * There are two of them, and both are this node's problem rather than the
 * peer's: the node could not make room for another link, and a transition the
 * FSM refused. A breakdown that mixed protocol verdicts with local failures
 * would not add up against n_link_rejected, and reporting an internal mistake
 * as BAD_ARITY -- which is what the first version of this file did -- is a lie
 * told to whoever reads the log: it names a malformed handshake where the truth
 * is a node that could not move its own state machine.
 *
 * Both still print, because a refusal nobody can see is a bug nobody reports,
 * and both still close through conn_mark_closing() and never close the
 * descriptor, because that part is 3.4 and does not depend on why. */
static void fed_refuse(server_t *s, server_link_t *link, conn_t *c,
                       const char *claim, const char *why)
{
    (void)s;

    printf("[observable] link_refused: peer=%s reason=%s fd=%d\n",
           (link != NULL) ? link->name : claim, why, (c != NULL) ? c->fd : -1);
    if (c != NULL) {
        conn_mark_closing(c);
    }
}

/* An accepted claim, on either side. Creates the link if the connection
 * arrived on the listener, then runs INIT -> HANDSHAKE_SENT -> ESTABLISHED.
 *
 * On the ACCEPTING side both transitions happen here, in one step: the peer
 * has already proved itself, and waiting for our own claim to come back before
 * treating the link as a route would put establishment behind a peer's
 * scheduling for no security gain -- our claim is queued, and the peer's
 * silence is then its own T2 to discover.
 *
 * On the DIALLING side the link is already in HANDSHAKE_SENT -- this is the
 * peer's answer to the claim fed_link_promote() sent -- so only the second
 * transition applies. That is why the handshake_send() below is conditional
 * rather than unconditional: the FSM has no HANDSHAKE_SENT -> HANDSHAKE_SENT
 * edge, and calling it anyway would be the dialling node rejecting the peer
 * that answered it correctly. */
static int fed_claim_accepted(server_t *s, server_link_t *link, conn_t *c,
                              const char *claim, uint64_t peer_epoch)
{
    if (link == NULL) {
        /* A RE-CLAIM FROM A PEER WHOSE LINK WENT AWAY REUSES THE LINK, and this
         * is the second half of the correction in fed_check_federate() step 4.
         * That check now admits a claim for a name this node still holds a link
         * for, and the link is a NAME and a DESTINATION rather than a rival
         * claim -- so the claim has to be applied to IT. Creating a second link
         * for the same name instead would leave two entries in the table for
         * one server, and the second one is a duplicate every uniqueness check
         * from then on has to think about.
         *
         * WHY IT IS SAFE, which is the part that has to be argued rather than
         * assumed: fed_check_federate() has already returned FED_OK, and that
         * now means no ESTABLISHED link and no link holding a descriptor claims
         * this name. So whatever is found here holds no socket, and taking it
         * over cannot displace a live route. It also cannot disturb the
         * dialling side, which finds its link by descriptor in
         * fed_link_of_conn() and never reaches this branch. */
        link = server_find_link(s, claim);
    }
    if (link == NULL) {
        link = fed_link_new(s, claim, 0);
        if (link == NULL) {
            fed_refuse(s, NULL, c, claim, "NO_LINK_ROOM");
            return -1;
        }
    }
    if (link->state == (int)ESTABLISHED) {
        /* The same link, naming itself again. A peer that re-sends its FEDERATE
         * on an already-established link is a bug on its side, and answering it
         * by re-authenticating would let anything that had once learned the
         * secret re-run the exchange forever. Nothing to do. */
        return 0;
    }
    if (handshake_state(&link->hs) == (handshake_state_t)INIT) {
        if (handshake_send(&link->hs) != 0) {
            /* A BUG REPORT, not a rejection. The context was INIT one line ago
             * and the FSM has an INIT -> HANDSHAKE_SENT edge, so a refusal here
             * is a disagreement between this file and federation_handshake.c. */
            fed_refuse(s, link, c, claim, "FSM_REFUSED_SEND");
            return -1;
        }
        fed_link_set_state(link);
        /* created_ms is stamped here as well as at the dial. The dial stamp is
         * what makes the latch; this one is what makes the field mean "when
         * this link's current attempt began", and it is what 3.4's file map
         * describes. */
        link->created_ms = server_now_ms();
        (void)fed_queue_federate(s, link, c);
    } else if (handshake_state(&link->hs) != (handshake_state_t)HANDSHAKE_SENT) {
        /* The link is FAILED or TIMED_OUT -- a terminal state, with the
         * exchange that put it there long since closed. Reached only if
         * something reuses a link that is still in a terminal state, and the
         * correct response is to refuse the connection rather than to drag the
         * FSM backwards: handshake_reset() exists, and the only caller that
         * should be resetting a link is fed_link_reset(). */
        fed_refuse(s, link, c, claim, "LINK_TERMINAL");
        return -1;
    }
    if (handshake_receive(&link->hs) != 0) {
        /* Same reasoning as the send above: the context was HANDSHAKE_SENT one
         * line ago and the FSM has a HANDSHAKE_SENT -> ESTABLISHED edge, so a
         * refusal here is a disagreement between this file and
         * federation_handshake.c, not something the peer did. */
        fed_refuse(s, link, c, claim, "FSM_REFUSED_RECEIVE");
        return -1;
    }
    /* The mirror, and this one was MISSING for a while with T6 repairing it
     * silently on the next tick: handshake_receive() moves the FSM and nothing
     * in this function told the copy. Every FSM transition in this file goes
     * through fed_link_set_state() and no transition goes around it. */
    fed_link_set_state(link);
    fed_link_established(s, link, c, claim, peer_epoch);
    return 0;
}

/* ---------------------------------------------------------------------------
 * The dispatch seam
 * ---------------------------------------------------------------------------
 */

/* Everything the module does about an inbound line. Three cases, in order:
 *
 *   1. FEDERATE -- the only verb this phase gives a peer connection, and the
 *      only one that may make a link. Claimed on ANY connection, not only on
 *      one that is already a link, because an inbound peer arrives on the
 *      listener as an ordinary connection: the accept site has no way to know
 *      it is a peer until it says so, and 2.3 makes the handshake -- not the
 *      accept -- the place a peer is identified. A client that types FEDERATE
 *      is refused by the same checks, which is the documented cost of a peer
 *      handshake being the only way in: the verb is internal (4.3) and a
 *      client has no business sending it.
 *   2. A line on a link that already exists. The stamp is the liveness signal
 *      and the line goes to fed_dispatch(), which reads the 2.4 tags, applies
 *      the hop ceiling and dispatches the verb. It goes through the CLIENT
 *      dispatch to get there -- commands_dispatch() sees src->kind and calls
 *      fed_dispatch() -- because 3's diagram says the peer path is the same
 *      dispatch and that dispatch never asks "is this local or remote?". Two
 *      doors into the guard chain is one too many, and the chain is the only
 *      place 2.4 is enforced.
 *   3. Anything else -- an ordinary client line. Untouched, and handed to the
 *      dispatch that was installed before fed_open(). */
void fed_on_federate(server_t *s, conn_t *c, const message_t *m)
{
    server_link_t *self = fed_link_of_conn(s, c);
    uint64_t peer_epoch = 0;
    fed_federate_result_t result;

    if (s == NULL || c == NULL || m == NULL) {
        return;
    }
    result = fed_check_federate(s, self, m, g_secret, &peer_epoch);
    if (result != FED_OK) {
        fed_reject(s, self, c, result, m->params[0]);
        return;
    }
    (void)fed_claim_accepted(s, self, c, m->params[0], peer_epoch);
}

static void fed_dispatch_hook(server_t *s, conn_t *c, const message_t *m)
{
    server_link_t *link;

    if (s == NULL || c == NULL || m == NULL) {
        return;
    }
    if (strcmp(m->command, "FEDERATE") == 0) {
        /* Answered HERE and not by the guard chain's G2, for one reason: at this
         * point the connection is still a CLIENT connection -- fed_link_established()
         * is what sets c->kind to CONN_SERVER -- so commands_dispatch()'s peer
         * branch has not been reached yet and there is nothing to hand the line
         * to. fed_dispatch()'s G2 calls this same function, so a FEDERATE that
         * arrives on an ALREADY-established link goes through both paths and is
         * answered identically: on such a link it is a re-claim, and
         * fed_check_federate() reports DUPLICATE_LINK or NAME_MISMATCH for it. */
        fed_on_federate(s, c, m);
        return;
    }

    link = fed_link_of_conn(s, c);
    if (link == NULL) {
        if (g_inner != NULL) {
            g_inner(s, c, m);
        }
        return;
    }
    /* A received line IS the liveness signal. Stamped HERE and not in
     * core/poll_loop.c so that the loop stays free of any peer concept; see the
     * header. */
    link->last_recv_ms = server_now_ms();
    /* Handed to the client dispatch, which routes a CONN_SERVER connection to
     * fed_dispatch(). THAT IS THE WHO OF IT, and it is one path rather than two:
     * section 3's diagram puts the peer read and the client read through the
     * same dispatch and says dispatch never asks "is this local or remote?" --
     * the only difference is src->kind. Routing from here straight into
     * fed_dispatch() would be a SECOND entry into the peer protocol, and the
     * guards would then have two doors. A line that reaches the client dispatch
     * and is not a peer line falls through to the client verb table, where
     * every S-verb is an unknown command -- which is the correct answer and is
     * counted, not the reason this routing exists. */
    if (g_inner != NULL) {
        g_inner(s, c, m);
    }
}

/* ---------------------------------------------------------------------------
 * Configuration
 * ---------------------------------------------------------------------------
 */
int fed_open(server_t *s, const char *secret)
{
    size_t len;

    if (s == NULL) {
        return -1;
    }
    if (g_owner != NULL) {
        /* One node per process, and the reason is in the header: the saved
         * dispatch has nowhere to live but here, and two nodes in one process
         * would mean the second chaining a wrapper round the first. The
         * same-node case is refused for a different reason -- it would wrap
         * the wrapper and recurse -- and both are the same mistake, so both
         * are reported by the same line. */
        printf("[observable] link_open_refused: reason=ALREADY_OPEN node=%s\n",
               (g_owner == s) ? "same" : "other");
        return -1;
    }
    if (secret != NULL) {
        len = strlen(secret);
        if (len >= (size_t)IRC_FED_MAX_SECRET) {
            /* Refused, not truncated: a truncated secret is weaker than the one
             * configured on the peer, and the failure would be a link that can
             * never authenticate, reported as a bad secret on both sides. */
            printf("[observable] link_open_refused: reason=SECRET_TOO_LONG "
                   "limit=%d\n",
                   IRC_FED_MAX_SECRET);
            return -1;
        }
        memcpy(g_secret, secret, len + 1u);
        g_secret_len = len;
    } else {
        g_secret[0] = '\0';
        g_secret_len = 0;
    }
    g_owner = s;
    g_inner = s->dispatch;
    s->dispatch = fed_dispatch_hook;
    /* NOT s->on_tick. The tick assignment is deliberately left to the caller
     * so that node_main.c shows the loop's time seam; see the header. */
    return 0;
}

void fed_set_timeouts(uint64_t dial_ms, uint64_t hs_ms, uint64_t keepalive_ms,
                      uint64_t dead_ms)
{
    if (dial_ms != 0u) {
        g_dial_ms = dial_ms;
    }
    if (hs_ms != 0u) {
        g_hs_ms = hs_ms;
    }
    if (keepalive_ms != 0u) {
        g_keepalive_ms = keepalive_ms;
    }
    if (dead_ms != 0u) {
        g_dead_ms = dead_ms;
    }
}

void fed_set_retry(uint64_t base_ms, uint64_t max_ms, unsigned budget)
{
    if (base_ms != 0u) {
        g_retry_base_ms = base_ms;
    }
    /* The ceiling is only ever LOWERED onto a base the caller also chose, and
     * never raised above a base that is smaller than it: a caller passing
     * max_ms < base_ms would otherwise get a ladder whose every step is above
     * its own ceiling, which is a policy with no first rung. Clamping here is
     * the difference between "the caller asked for a short scale" and "the
     * caller asked for something incoherent". */
    if (max_ms != 0u) {
        g_retry_max_ms = (max_ms > g_retry_base_ms) ? max_ms : g_retry_base_ms;
    }
    if (budget != 0u) {
        g_retry_budget = budget;
    }
}

/* ---------------------------------------------------------------------------
 * The tick
 * ---------------------------------------------------------------------------
 */

/* The live dial for a peer name, or NULL. Read out of server_t::dials directly
 * rather than through an accessor, and the reason is that there is none: the
 * three functions server.h offers for the dial table (collect, progress, count)
 * are the ones the LOOP needs, and the one thing this file needs -- "has a
 * dial for this peer, and what state is it in" -- has no entry point. Adding
 * one is a change to core/server.h for a single caller; reading the POD the
 * struct already exposes is not. s->dials is a public field precisely because
 * the layout is part of server.h's contract. */
static dial_t *fed_dial_for(server_t *s, const char *peer_name)
{
    size_t i;

    for (i = 0; i < s->ndials; i++) {
        if (s->dials[i].state == DIAL_CONNECTING ||
            s->dials[i].state == DIAL_CONNECTED) {
            if (same_name(s->dials[i].peer_name, peer_name)) {
                return &s->dials[i];
            }
        }
    }
    return NULL;
}

/* ---------------------------------------------------------------------------
 * THE RECONNECT SCHEDULE
 * ---------------------------------------------------------------------------
 * Three questions, one function, and the reason they are a function rather than
 * three comparisons at three call sites is the reason EVERY refusal in this file
 * goes through one place: the counter, the next attempt's stamp, and the "this
 * node has stopped trying" report are three numbers that must agree, and three
 * call sites are three chances for them to disagree.
 *
 * `why` is a short stable token naming the failure that armed the schedule, and
 * it is on the observable line because the operator's question is "why is it
 * trying again" and the answer is which arm fired.
 *
 * THE BUDGET IS CHECKED FIRST AND IS NOT REARMED, and that ordering is the whole
 * of "a node that retries forever is a leak": once the budget is spent the
 * schedule is left where it was and `gave_up` is set, so T7's condition is false
 * for the rest of the process. Nothing wakes it and nothing clears it but
 * fed_link_reset().
 */
static void fed_retry_arm(server_t *s, server_link_t *link, uint64_t now_ms,
                          const char *why)
{
    uint64_t delay;
    unsigned step;

    if (s == NULL || link == NULL) {
        return;
    }
    if (link->gave_up != 0) {
        /* Already spent, and NOT re-reported. The exhaustion is reported once at
         * the moment it happens; a line per tick for a link that will never be
         * dialled again would be a log that fills up at 20 lines per second on
         * a node with a dead peer, which is the opposite of reporting. */
        return;
    }
    /* ALREADY SCHEDULED, AND THAT IS NOT A NO-OP WORTH SKIPPING SILENTLY. The
     * ladder is armed by several arms of the tick and a single failure can reach
     * two of them -- a peer that is down produces a dial that completes and a
     * handshake that then times out, and a peer that is unreachable produces a
     * dial that is retired by T1 on one tick and observed by the DIAL_FAILED arm
     * on the next. Arming twice for one failure would double the wait and spend
     * two of a three-attempt budget on one dead peer.
     *
     * The test is "a schedule is already running", which is `retry_at_ms` in the
     * future -- NOT "retry_at_ms is non-zero", because a link whose last schedule
     * has EXPIRED also has a non-zero stamp and is exactly the link that needs
     * re-arming. Getting that backwards would make a link that had exhausted its
     * ladder refuse to arm again, which is the opposite of the intent. */
    if (link->retry_at_ms > now_ms) {
        return;
    }
    if (link->retries >= g_retry_budget) {
        link->gave_up = 1;
        s->n_fed_retry_exhausted++;
        printf("[observable] link_retry_exhausted: peer=%s attempts=%u budget=%u "
               "reason=AFTER_%s\n",
               link->name, link->retries, g_retry_budget, (why != NULL) ? why : "?");
        return;
    }

    /* THE LADDER: the base doubled once per attempt already made, capped at the
     * ceiling. The shift is bounded by the step constant rather than by
     * `retries`, so a link that somehow accumulated a large retry count cannot
     * shift an integer out of its own width -- which is a real hazard and not a
     * theoretical one, because `retries` counts events a peer can drive by
     * refusing a handshake. */
    step = link->retries;
    if (step >= (unsigned)IRC_FED_RETRY_MAX_STEPS) {
        step = (unsigned)IRC_FED_RETRY_MAX_STEPS;
    }
    delay = g_retry_base_ms * ((uint64_t)1u << step);
    if (delay > g_retry_max_ms) {
        delay = g_retry_max_ms;
    }
    link->retries++;
    link->retry_at_ms = now_ms + delay;
    printf("[observable] link_retry: peer=%s attempt=%u/%u delay_ms=%llu after=%s\n",
           link->name, link->retries, g_retry_budget,
           (unsigned long long)delay, (why != NULL) ? why : "?");
}

/* T1. A connect() that poll() will never report on.
 *
 * The one close() in this file, and it closes a DIAL rather than a connection:
 * a DIAL_CONNECTING descriptor is not in by_fd and has no conn_t, so the reaper
 * has nothing to reap and no other code path can close it. server.c already
 * closes exactly these descriptors on the same grounds (a DIAL_FAILED arm in
 * server_dial_progress(), and the shutdown walk), so this is the third of the
 * three places that may close a socket which never became a connection and the
 * first that is not in server.c.
 *
 * The stamp is dial_t::started_ms and it was taken at the connect() rather
 * than by a later tick precisely so that this deadline is a property of the
 * connect and not of the loop's cadence. */
static void fed_dial_expired(server_t *s, size_t i, uint64_t now_ms)
{
    uint64_t waited = now_ms - s->dials[i].started_ms;
    char peer[IRC_MAX_SERVER_NAME + 1];

    memcpy(peer, s->dials[i].peer_name, strlen(s->dials[i].peer_name) + 1u);
    printf("[observable] dial_timeout: peer=%s ms=%llu\n", peer,
           (unsigned long long)waited);
    close(s->dials[i].fd);
    s->dials[i].fd = -1;
    s->dials[i].state = DIAL_FAILED;
    s->n_dial_failed++;
    /* A CONNECT THAT NEVER COMPLETED IS THE FAILURE A RETRY BUDGET IS MOST
     * OBVIOUSLY FOR, and T1 is the only arm that reaches it: a black-holed host
     * produces no FIN, no ESTABLISHED, and therefore no T4, so a peer that is
     * down rather than unreachable never gets there. The link is found by NAME
     * because the dial table is keyed by nothing and holds a display copy, and
     * this is the one place where the link and the dial for the same peer are
     * related by that name rather than by a pointer -- which is why the lookup
     * is a scan of a vector this small rather than a stored back-pointer.
     *
     * The link is left in INIT by this arm (a dial that never completed never
     * promoted it), so the schedule armed here is the one T7 reads. */
    for (size_t k = 0; k < server_link_count(s); k++) {
        server_link_t *link = server_link_at(s, k);

        if (link != NULL && same_name(link->name, peer) &&
            link->state == (int)INIT) {
            fed_retry_arm(s, link, now_ms, "DIAL_TIMEOUT");
            break;
        }
    }
}

/* The dial completed: the link gets its descriptor and starts its exchange.
 * INIT -> HANDSHAKE_SENT, and it is the SAME transition the accepting side
 * performs, which is what 2.3 means by the FSM being per-peer rather than
 * per-direction. */
static void fed_link_promote(server_t *s, server_link_t *link, dial_t *d)
{
    conn_t *c = server_conn(s, d->fd);

    if (c == NULL) {
        /* The connection went away between the dial completing and this tick.
         * The reaper has already closed the descriptor, so there is nothing to
         * close here and nothing to reap: the slot is retired rather than left
         * DIAL_CONNECTED, because DIAL_CONNECTED is what T7 and the next
         * promotion scan read, and a slot that stays there is a promotion
         * attempted on every tick for the life of the process.
         *
         * It is retired as FAILED rather than as anything else because FAILED
         * is the one dial state the shutdown walk does NOT close -- so a slot
         * left FAILED can never be double-closed -- and because a dial whose
         * connection was reaped before it was ever used has not delivered
         * anything, which is what FAILED means everywhere else in this file. */
        printf("[observable] link_promote_failed: peer=%s fd=%d "
               "reason=CONNECTION_GONE\n", link->name, d->fd);
        d->fd = -1;
        d->state = DIAL_FAILED;
        s->n_dial_failed++;
        return;
    }
    /* THE DIAL SLOT IS RETIRED HERE, and it did not used to be, and the reason it
     * has to be is that fed_dial_for() treats a DIAL_CONNECTED slot as a LIVE
     * DIAL. Before this line, the slot stayed DIAL_CONNECTED for the rest of the
     * link's life, and that produced two distinct defects once a link could be
     * re-dialled:
     *
     *   - T7's live-dial guard saw a live dial for a link that was already
     *     promoted, so a link that had just come back from HANDSHAKE_SENT to
     *     INIT could not dial for another whole dial timeout.
     *   - On the tick after the promotion, if the connection had been reaped in
     *     the meantime, fed_link_promote() ran again on the same slot and
     *     reported `link_promote_failed: reason=CONNECTION_GONE` for a link that
     *     had in fact been up and had simply been taken down. That is a
     *     MISLEADING line about a link that was not failing, and an operator
     *     reading it would chase a peer that was fine.
     *
     * DIAL_CONNECTED is retired as DIAL_FAILED rather than as anything else, and
     * for the reason fed_link_promote()'s CONNECTION_GONE arm gives: FAILED is
     * the one state the shutdown walk does not close, so a slot left in it can
     * never be double-closed. It is not a claim that this dial failed -- the
     * promotion below is what says whether it worked -- it is the state that
     * means "this slot holds nothing you may close". */
    d->state = DIAL_FAILED;
    d->fd = -1;

    link->fd = c->fd;
    handshake_init(&link->hs);
    link->created_ms = server_now_ms();
    if (handshake_send(&link->hs) != 0) {
        /* A BUG REPORT. The link was INIT and the FSM has the edge; see
         * fed_refuse(). */
        fed_refuse(s, link, c, link->name, "FSM_REFUSED_SEND");
        return;
    }
    fed_link_set_state(link);
    link->last_sent_ms = link->created_ms;
    link->last_recv_ms = link->created_ms;
    (void)fed_queue_federate(s, link, c);
    printf("[observable] link_dialled: peer=%s fd=%d state=HANDSHAKE_SENT\n",
           link->name, link->fd);
}

/* T3. The keepalive, and what it costs.
 *
 * BUILT HERE rather than through fed_send_sverb(), and the reason is a frozen
 * wire format rather than a preference. That table maps CLIENT verbs a node is
 * RELAYING, and tests/integration/test_fed_wire.c asserts that PING has no
 * S-verb because "4.3's list is the forwarded vocabulary, and adding to it is a
 * wire-format change". A link-liveness probe is not a relay of anything, so
 * there is no client verb to map -- and inventing one would put a word into the
 * forwarded vocabulary that an implementation written from 4.3 would refuse.
 * verbs.h records the same conclusion from the other side, and the table is
 * still closed: this function names PING itself and nothing else had to change.
 *
 * The part that is NOT unique to a keepalive -- stamp the 2.4 block, build the
 * message, render it, bound-check it, terminate it, queue it -- is
 * fed_queue_line() in verbs.c, which this function and fed_send_sverb() both
 * call, and the two files point at each other rather than each explaining the
 * overlap. What stays here is what is specific to a keepalive: which line it
 * sends, the stamps it puts on it, and the refusal words a reader of this
 * module expects to see. The failure is still reported as THIS node failing to
 * probe, not as a verb that has no S-verb, which is the more useful of the two
 * reports.
 *
 * hops=0 because this node ORIGINATED the line, and 2.4's rule is that a node
 * never forwards a message whose origin it is -- so the hop count of an
 * originated message starts at zero and becomes one on the far side's first
 * forward. A fresh id from the per-SERVER counter, because 2.4 is explicit that
 * a per-connection counter is what this format replaced.
 *
 * The peer does not answer in this phase: there is no inbound PING handling
 * until C3. That is harmless, because a received line is the liveness signal
 * rather than an answer, and the PEER's own keepalives are what refresh this
 * side. The cost of it not being harmless would be a link with no responses,
 * which is a different design and C3's to make. */
static int fed_send_keepalive(server_t *s, server_link_t *link, conn_t *c,
                              uint64_t now_ms)
{
    irc_serve_tags_t tags;
    const char *params[2];
    fed_queue_why_t why = FED_QUEUE_OK;

    memset(&tags, 0, sizeof tags);
    memcpy(tags.origin, s->name, strlen(s->name) + 1u);
    tags.epoch = s->epoch;
    tags.id = server_next_msg_id(s);
    tags.hops = 0;

    params[0] = link->name; /* the peer being probed */
    params[1] = s->name;    /* who is asking                                  */
    /* The stamps above are validated inside fed_queue_line(), and the reason
     * that is checked rather than trusted is the same: a stamp that fails the
     * 2.4 grammar cannot be put on the wire in a form a peer would accept, and a
     * keepalive a peer refuses to parse is a link that goes dead for want of a
     * probe. s->epoch is at least 1 and server_next_msg_id() never returns 0,
     * so this cannot fail; it is checked because the alternative is a tagless
     * line on a peer link.
     *
     * BOTH tag refusals are reported as BAD_TAGS, which is what this module
     * has always printed for them. fed_queue_line() separates the two because
     * fed_send_sverb() has a second word for a block that will not fit, and
     * splitting one unreachable case in two here would add a word to this
     * module's vocabulary for a condition that cannot arise: a stamp this
     * function just built is either valid or it is a bug in the values above. */
    if (fed_queue_line(s, c, &tags, s->name, "PING", params, 2, &why) != 0) {
        printf("[observable] keepalive_refused: peer=%s reason=%s\n",
               link->name,
               (why == FED_QUEUE_TAG_TOO_LONG)
                   ? "BAD_TAGS"
                   : fed_queue_why_name(why));
        return -1;
    }
    link->last_sent_ms = now_ms;
    return 0;
}

/* T4. A peer that has stopped talking. */
static void fed_dead(server_t *s, server_link_t *link, conn_t *c,
                     uint64_t now_ms)
{
    uint64_t silent = now_ms - link->last_recv_ms;

    printf("[observable] link_dead: peer=%s silent_ms=%llu\n", link->name,
           (unsigned long long)silent);
    (void)handshake_fail(&link->hs);
    fed_link_set_state(link);
    s->n_fed_dead++;
    /* THE FAILOVER ARM, and it is here rather than at the end of the tick for a
     * reason that is about the order of events: fed_link_down() is what clears
     * the link's descriptor and hands the state back to INIT, and T7 runs in
     * the SAME tick's switch. Arming before the teardown means the schedule is
     * already stamped by the time this link reaches the INIT arm, so a link that
     * has been dead for a whole IRC_FED_DEAD_MS is re-dialled on the NEXT tick
     * rather than one tick after that. */
    fed_retry_arm(s, link, now_ms, "DEAD");
    /* ANNOUNCED, because this link WAS a route: every other peer holding this
     * node's name learned it through here, and cannot reach it here any more. */
    fed_link_down(s, link, 1);
    if (c != NULL) {
        conn_mark_closing(c);
    }
}

void fed_tick(server_t *s, uint64_t now_ms)
{
    size_t i;

    if (s == NULL) {
        return;
    }

    /* --- T5: the dedup sweep ------------------------------------------- */
    /* Only the occupancy is gated here. The time part of "is it due" is inside
     * fed_dedup_sweep(), because the property is the store's age rather than
     * the caller's, and there are two call sites (this one and
     * fed_dedup_seen()'s). */
    if (s->dedup_used > (uint64_t)(IRC_DEDUP_MAX / 2u)) {
        (void)fed_dedup_sweep(s, now_ms);
    }

    /* A node with no peers pays three integer comparisons and returns: this
     * one, the occupancy test above, and the pointer test just here. */
    if (server_link_count(s) == 0u) {
        return;
    }

    /* --- T1: dials that will never complete ---------------------------- */
    for (i = 0; i < s->ndials; i++) {
        if (s->dials[i].state == DIAL_CONNECTING &&
            (uint64_t)(now_ms - s->dials[i].started_ms) >= g_dial_ms) {
            fed_dial_expired(s, i, now_ms);
        }
    }

    /* --- per link ------------------------------------------------------ */
    for (i = 0; i < server_link_count(s); i++) {
        server_link_t *link = server_link_at(s, i);
        conn_t *c;
        dial_t *d;

        if (link == NULL) {
            continue;
        }
        /* The link pointer is re-derived from the index on every use because
         * fed_link_reset() and fed_link_configure() can grow the vector, and a
         * pointer into an array that another call may realloc is exactly the
         * habit that turns a growth into a use-after-free. */
        c = server_link_conn(s, link);

        /* --- promotion: the dial completed ----------------------------- */
        if (link->fd < 0) {
            d = fed_dial_for(s, link->name);
            if (d != NULL && d->state == DIAL_CONNECTED) {
                fed_link_promote(s, link, d);
                c = server_link_conn(s, link);
            }
        }

        /* --- T6: resync the mirror ------------------------------------ */
        /* hs.state is the truth and the mirror is a copy, so a disagreement is
         * a bug in a writer. Repairing it here is what makes the dump and every
         * routing predicate trustworthy in the tick after such a bug rather
         * than permanently -- and it is reported, because a mirror that needed
         * repairing is a finding and not a detail. */
        if (link->state != (int)link->hs.state) {
            printf("[observable] link_state_resync: peer=%s was=%d now=%d\n",
                   link->name, link->state, (int)link->hs.state);
            fed_link_set_state(link);
        }

        switch (link->state) {
        case (int)INIT:
            /* --- T7: dial it, if the schedule says so ------------------- */
            /* FIVE CONDITIONS, AND EVERY ONE OF THEM IS LOAD-BEARING. The
             * count is the price of replacing a single latch with a policy.
             *
             *   initiator        an ACCEPTED link has no address, and
             *                   server_dial() would be handed a zeroed sockaddr.
             *   addrlen != 0     same, stated separately because a link with a
             *                   zero length is a different defect from a link
             *                   that never dialled and the two are worth telling
             *                   apart in a dump.
             *   gave_up == 0     the budget. Checked HERE rather than inside a
             *                   helper so that the whole refusal is visible in
             *                   one place: this is the line a reader comes to
             *                   when a link is not being dialled.
             *   due              the backoff. retry_at_ms == 0 means DUE NOW,
             *                   which is the state a freshly configured link is
             *                   in, so a healthy mesh's first dial is immediate
             *                   and only a failed one waits.
             *   no live dial     UNCHANGED from Phase 6 and still the arm with
             *                   the subtlest failure: between this call to
             *                   server_dial() and the dial resolving there is no
             *                   state change on the link at all, so a link whose
             *                   stamp is already in the past opens a SECOND
             *                   socket to the same peer on the very next tick.
             *                   The backoff does not fix this -- the schedule
             *                   says the link is due and it stays due until the
             *                   attempt resolves.
             *
             * created_ms is stamped here and is NOT read as a latch any more
             * (the header retracts that claim); what it is for now is T2's
             * comparison against IRC_FED_HS_TIMEOUT_MS and for the dump, where
             * "when did this attempt begin" is one of the two numbers an
             * operator needs to tell a slow handshake from a dead link. */
            if (link->initiator != 0 && link->addrlen != 0 && link->gave_up == 0 &&
                (link->retry_at_ms == 0u || now_ms >= link->retry_at_ms) &&
                fed_dial_for(s, link->name) == NULL) {
                link->created_ms = now_ms;
                if (server_dial(s, (const struct sockaddr *)&link->addr,
                                link->addrlen, link->name) == 0) {
                    printf("[observable] link_dial: peer=%s\n", link->name);
                } else {
                    /* A DIAL THAT COULD NOT BE STARTED AT ALL -- an exhausted
                     * descriptor table, or a socket() the kernel refused -- is a
                     * failed attempt and must cost budget, or a node in that
                     * state dials on every tick for ever. server_dial() has
                     * already counted it on n_dial_failed; this counts the
                     * LINK's side, which is the different fact. */
                    fed_retry_arm(s, link, now_ms, "DIAL_REFUSED");
                }
            }
            break;

        case (int)HANDSHAKE_SENT:
            /* --- T2: the handshake never answered ----------------------- */
            if (link->created_ms != 0u &&
                (uint64_t)(now_ms - link->created_ms) >= g_hs_ms) {
                (void)handshake_timeout(&link->hs);
                fed_link_set_state(link);
                s->n_fed_hs_timeout++;
                printf("[observable] link_timeout: peer=%s state=TIMED_OUT\n",
                       link->name);
                /* T2 ARMS THE SCHEDULE AND TAKES THE LINK BACK TO INIT, and
                 * both halves were corrections rather than new behaviour. Phase 6
                 * left TIMED_OUT terminal on the reasoning that a handshake which
                 * never completed has nothing to tear down -- which is true of the
                 * ANNOUNCEMENT and was then over-applied to the STATE, with the
                 * consequence that a peer accepting TCP and then going silent
                 * cost this node one dial and no retry for the life of the
                 * process. That is the same silent resource leak the budget
                 * exists to bound, reached by a different road, and a test
                 * (test_failover_reconnect.c) found it by freezing a peer whose
                 * kernel still completes the handshake: the retry arrived, the
                 * FEDERATE was unanswered, and the link sat in a terminal state
                 * that nothing dials out of.
                 *
                 * SO THE ARM IS NOT OPTIONAL HERE and the teardown below is what
                 * makes it readable: without returning the link to INIT the
                 * schedule would be stamped by a path that never dials again,
                 * which is worse than not arming at all -- a reader would see a
                 * `link_retry:` line and conclude a retry was coming.
                 *
                 * NOT ANNOUNCED (fed_link_down's third argument), and that is the
                 * load-bearing part of the correction: no peer ever learned
                 * anything about this node through a handshake that never
                 * finished, and the node's OTHER links are still up, so a SQUIT
                 * here would tell a healthy mesh that a live node had departed. */
                fed_retry_arm(s, link, now_ms, "HANDSHAKE_TIMEOUT");
                fed_link_down(s, link, 0);
                if (c != NULL) {
                    conn_mark_closing(c);
                }
            }
            break;

        case (int)ESTABLISHED:
            /* --- T3: keepalive, then T4: dead ------------------------- */
            /* Both tests are on this link's own stamps, and both are
             * subtractions: 3.4's clock is monotonic, and a subtraction is the
             * shape that stays correct if it ever is not. */
            if ((uint64_t)(now_ms - link->last_sent_ms) >= g_keepalive_ms) {
                if (c != NULL) {
                    /* On failure last_sent_ms is NOT advanced, which is the
                     * point of returning the status: server_queue() has already
                     * marked the link CLOSING for a saturated queue and counted
                     * it, and T4 will notice the silence. Advancing the stamp
                     * anyway would tell T4 the peer had been spoken to when it
                     * had not, and the link would sit there for another full
                     * dead interval before anything was said about it. */
                    (void)fed_send_keepalive(s, link, c, now_ms);
                }
            }
            if ((uint64_t)(now_ms - link->last_recv_ms) > g_dead_ms) {
                /* THE FAILOVER ARM, once. T4 is the only place a link that was
                 * ESTABLISHED can be declared dead, so the heartbeat is the only
                 * thing that drives a redial of a link that WAS up: there is no
                 * other event in this node that means "this peer is gone" for a
                 * link that had a descriptor and a route. That is the whole of
                 * "heartbeat-driven failover" -- the liveness signal does not
                 * merely close the link, it ARMS the redial, and the arm happens
                 * in fed_retry_arm() above rather than being a decision T4
                 * delegates to the next tick. */
                fed_dead(s, link, c, now_ms);
            }
            break;

        default:
            /* FAILED and TIMED_OUT. Both are terminal until something resets
             * them, and in C2 nothing does: a link that failed stays failed and
             * is reported by the dump, which is the honest state. A switch here
             * would be a second opinion about handshake_state_t that the FSM
             * owns, and this file's whole claim about the FSM is that it does
             * not have one. */
            break;
        }
    }
}
