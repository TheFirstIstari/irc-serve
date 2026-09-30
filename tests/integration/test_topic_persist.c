/* test_topic_persist.c -- channel topic persistence across a reconnect, on the
 * wire, against the real binary.
 *
 * docs/SERVER_DESIGN.md 4.1 (TOPIC), 4.4 (331, 332, 333), 2.2 (a channel with no
 * members is disposed, and the topic is one of its fields), and 7/Phase 7's
 * allocation of this test. It was a CTest skip (return 77) from the first phase
 * and is now a real test of real behaviour: the feature it was named for --
 * topic persistence across reconnects -- is implemented, and this is the test
 * that would notice if it stopped working.
 *
 * ---------------------------------------------------------------------------
 * WHAT "PERSISTENCE" IS HERE, STATED PRECISELY BECAUSE THE NAME IS AMBIGUOUS
 * ---------------------------------------------------------------------------
 * The feature is THIS: a channel's topic survives the channel being disposed.
 * chan_dispose_if_empty() (2.2) frees a channel with no local members and no
 * member-server, and it is right to -- holding one per channel NAME a client ever
 * typed would be an unbounded store reachable from the wire. The topic is the one
 * field whose loss a user can SEE, so it is copied into a bounded cache on
 * server_t on the way down (channel.c's server_topic_remember) and copied back
 * into a channel that is being CREATED (server_topic_restore). Where that state
 * lives is argued there and in server.h; this file is the wire-level evidence
 * that it works.
 *
 * IT IS NOT DISK PERSISTENCE. A topic does not survive a node restart, because
 * 3.4 forbids a write inside the event loop and because an on-disk topic store is
 * a new deployment artifact and a new way for a topic to be wrong. Nothing here
 * claims otherwise and nothing here tests it -- a test that asserted it would be
 * asserting a feature this phase does not have. channel.h records the three
 * alternatives that were considered and why this one was chosen.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS FILE IS UNDER tests/integration AND NOT tests/protocol
 * ---------------------------------------------------------------------------
 * Because every assertion here is about bytes on a socket, and the harness that
 * reaches them (tests/harness/irc_client.h and node_fixture.h) is built by
 * tests/integration/CMakeLists.txt, which is added AFTER tests/protocol. A test
 * that cannot reach a node cannot test what this feature is. The CTest name is
 * unchanged -- TopicPersistence -- so the skip list, the stats workflow and
 * anything that has ever seen this test keep naming the same thing.
 *
 * ---------------------------------------------------------------------------
 * WHAT IS ASSERTED, AND WHY EACH CASE IS HERE
 * ---------------------------------------------------------------------------
 * The two forms of "the client went away" are different code paths and the file
 * covers both, because covering only one is what a partial implementation looks
 * like:
 *
 *   PART     handle_part() reaches chan_dispose_if_empty() through the handler.
 *   DROPPED  A TCP connection that simply closes reaches it through
 *            chan_conn_gone(), called by the reaper. This is the ordinary end of
 *            a connection and it is what a "reconnect" means nine times out of
 *            ten: a client that reconnects has, almost always, dropped.
 *
 * And the thing that makes a topic a CHANNEL's rather than a connection's is
 * asserted directly: alice sets the topic, bob sets nothing at all, and both
 * rejoins are bob's. A cache keyed by anything to do with the setter would pass a
 * test in which the setter is also the rejoiner, which is the shape almost every
 * naive test of this takes.
 *
 * 333 IS ASSERTED AS A WHOLE, and it is the assertion with the most in it. 333
 * carries the setter AND the time; a cache that restored only the text would make
 * 333 name whoever rejoined and the moment they rejoined, and those numbers are
 * the only way a user can tell. So 333 is parsed with sscanf and all three of
 * its fields are checked -- the setter, which must still be alice and must be
 * the display spelling alice chose, and a <time> that is neither zero nor in the
 * future. conn_t::signon_at gets the same three checks in test_queries.c, and the
 * reason is the same: a numeric carrying a plausible number in a field that means
 * nothing is a numeric that lies.
 *
 * AND THE NEGATIVES, which are the half with teeth:
 *   - 331 ("No topic is set") must be ABSENT after a restore. A node that answered
 *     both 331 and 332 would satisfy every positive check here.
 *   - A CLEARED topic must NOT come back. `TOPIC #chan :` followed by everybody
 *     leaving must leave a rejoiner with 331, because a cache that remembered the
 *     old text would put back a topic the user deliberately removed.
 *   - A channel nobody ever gave a topic must still answer 331 after a dispose
 *     and a rejoin, so a cache that invented a topic would be caught.
 *   - topic_cache_full must be 0, so "the topic survived" cannot be true merely
 *     because nothing was ever disposed.
 *   - The channel must be DISPOSED exactly the three times this test empties it
 *     and no more. A PART that disposed a channel with a member still on it would
 *     raise that count, and it is the only wire-visible way to tell the live path
 *     from the cached one.
 *
 * NO sleep() ANYWHERE (6.3): every wait is a select()-driven deadline inside
 * tc_expect() or nf_expect(), and every negative assertion is scoped to a window
 * closed by a PING drain. A bare tc_expect() searches the whole accumulated
 * buffer, so a second ` 332 ` would match the first and return instantly and the
 * wait covering the command under test would never happen.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

#define T_READY_MS 15000
#define T_IO_MS 15000

#define BIN_NAME "irc.test"
#define OBSERVED_HOST "127.0.0.1"
#define CHAN "#PERSIST"
#define OTHER "#OTHER"

/* The topic alice sets. It begins with a space and contains others, and BOTH
 * matter for the same reason test_queries.c gives about an away message: 3.2's
 * formatter colons a trailing parameter only when the value needs one, so a topic
 * that is a single word would render uncolonned and every needle in this file
 * would be waiting for a colon the node deliberately does not send. Choosing a
 * topic that needs the colon is also the form every human-written topic has. */
#define TOPIC_TEXT " the original topic of " CHAN

static size_t g_opened;

typedef struct {
    test_client_t c;
    char          nick[72];
} client_t;

static void client_open(client_t *cl, nf_node_t *node, const char *nick)
{
    char line[512];

    tc_init(&cl->c);
    (void)snprintf(cl->nick, sizeof cl->nick, "%s", nick);
    g_opened++;
    TF_CHECK_MSG(tc_connect(&cl->c, node->port) == 0, "tc_connect(%s) failed",
                 nick);
    (void)snprintf(line, sizeof line, "NICK %s", nick);
    TF_CHECK_MSG(tc_send(&cl->c, line) == 0, "NICK send failed");
    (void)snprintf(line, sizeof line, "USER %s 0 * :Real %s", nick, nick);
    TF_CHECK_MSG(tc_send(&cl->c, line) == 0, "USER send failed");
    TF_CHECK_MSG(tc_expect(&cl->c, " 001 ", T_IO_MS) == 0, "%s did not register",
                 nick);
    TF_CHECK_MSG(tc_send(&cl->c, "PING :reg-drain") == 0, "PING send failed");
    TF_CHECK_MSG(tc_expect(&cl->c, "PONG ", T_IO_MS) == 0,
                 "%s: no PONG after registration", nick);
}

static void client_join(client_t *cl, const char *channel)
{
    char line[128];
    char needle[160];

    (void)snprintf(line, sizeof line, "JOIN %s", channel);
    (void)snprintf(needle, sizeof needle, ":%s 366 %s ", BIN_NAME, cl->nick);
    TF_CHECK_MSG(tc_send(&cl->c, line) == 0, "tc_send(%s) failed", line);
    TF_CHECK_MSG(tc_expect(&cl->c, needle, T_IO_MS) == 0,
                 "%s: no 366 after JOIN %s", cl->nick, channel);
}

static unsigned g_drain_seq;
static unsigned g_last_seq;

static size_t mark(client_t *cl)
{
    char line[64];
    char needle[96];
    const char *at;

    g_drain_seq++;
    g_last_seq = g_drain_seq;
    (void)snprintf(line, sizeof line, "PING :m%u", g_drain_seq);
    (void)snprintf(needle, sizeof needle, "PONG %s m%u\r\n", BIN_NAME,
                   g_drain_seq);
    TF_CHECK_MSG(tc_send(&cl->c, line) == 0, "mark PING send failed");
    TF_CHECK_MSG(tc_expect(&cl->c, needle, T_IO_MS) == 0, "no PONG for %s", line);
    at = strstr(tc_buffer(&cl->c), needle);
    TF_CHECK_MSG(at != NULL, "the mark PONG vanished from the buffer");
    return (at != NULL) ? (size_t)(at - tc_buffer(&cl->c)) : 0u;
}

/* Wait for the wall clock to move past `since`, by draining the client while we
 * do it.
 *
 * The harness's tc_drain() is this helper. It was declared in irc_client.h with a
 * full contract and had NO DEFINITION, so a caller did not link; this function was
 * a local copy written to route around that. The declaration said the capability
 * existed, so the real defect was the missing definition, and it is fixed in
 * irc_client.c rather than papered over with a second copy of the thing tc_drain()
 * exists to be.
 *
 * `since` is the timestamp we are waiting to pass. It is not needed to compute the
 * answer -- the wait is for wall time to move, not for bytes to arrive -- but it is
 * part of the call contract so the caller can assert on progress. */
static unsigned long long wait_second_advances(client_t *cl,
                                               unsigned long long since,
                                               int timeout_ms)
{
    int eof = 0;

    (void)since;
    (void)tc_drain(&cl->c, timeout_ms, &eof);
    return (unsigned long long)time(NULL);
}

/* Settle the CHILD'S OUTPUT after a mark.
 *
 * A PONG arriving on a socket and the corresponding line reaching the parent's
 * captured stdout are two different events, and the second is not implied by the
 * first: tc_expect() returns the moment the PONG is in hand, which can be before
 * the harness has pumped the node's next stdout line. Reading node.out at that
 * point is a race, and a race in a test is a test that passes on a fast machine.
 *
 * The fix is a wait and not a sleep, and the thing it waits for is the node's own
 * `[observable] ping: ... token=mN` line -- written when the node processed the
 * PING, which is after everything queued before it, including a channel disposal
 * and the topic_persist line that disposal prints. nf_expect() returns
 * immediately if the needle is already there and pumps until it appears if it is
 * not, so this is correct either way and costs nothing in the common case.
 *
 * The alternative was tried and is wrong: asserting the `topic_persist` line
 * directly after waiting for the preceding `chan_destroy` line fails about one
 * run in three under -j 12, because the dispose prints BEFORE it remembers the
 * topic and the parent's pump had not caught up. */
static void settle_log(nf_node_t *node)
{
    char needle[64];

    (void)snprintf(needle, sizeof needle, "token=m%u", g_last_seq);
    TF_CHECK_MSG(nf_expect(node, needle, T_IO_MS) == 0,
                 "the node never reported answering mark PING m%u, so a read of "
                 "its output would be a race rather than a fact",
                 g_last_seq);
}

static void expect_in_window(client_t *cl, size_t from, size_t end,
                             const char *what, const char *want)
{
    const char *base = tc_buffer(&cl->c);
    const char *at;

    TF_CHECK_MSG(end > from,
                 "%s: the window was never closed (from=%zu end=%zu)", what, from,
                 end);
    at = strstr(base + from, want);
    TF_CHECK_MSG(at != NULL, "%s: expected the exact line \"%s\"", what, want);
    if (at == NULL) {
        return;
    }
    TF_CHECK_MSG(at < base + end,
                 "%s: \"%s\" appears only AFTER the window closed, so it was not "
                 "an answer to the command under test",
                 what, want);
    TF_CHECK_MSG(at == base + from || at[-1] == '\n',
                 "%s: \"%s\" is not at the start of a line: it is the tail of a "
                 "longer one",
                 what, want);
}

static void expect_absent_in_window(client_t *cl, size_t from, size_t end,
                                    const char *what, const char *needle)
{
    const char *base = tc_buffer(&cl->c);
    size_t count = 0;

    TF_CHECK_MSG(end > from,
                 "%s: the window was never closed (from=%zu end=%zu), so \"did "
                 "not appear\" would prove nothing",
                 what, from, end);
    for (const char *p = base + from; p < base + end;) {
        const char *hit = strstr(p, needle);

        if (hit == NULL || hit >= base + end) {
            break;
        }
        count++;
        p = hit + strlen(needle);
    }
    TF_CHECK_MSG(count == 0,
                 "%s: \"%s\" appeared %zu time(s) in the window and must not have "
                 "appeared at all",
                 what, needle, count);
}

/* Non-overlapping occurrences of `needle` in `hay`. Over the NODE's own output
 * rather than a socket, and the harness has no helper for that direction --
 * nf_expect() can only assert that a needle IS present. The node's stdout is its
 * observable output by design, which is the same thing the other tests read
 * through nf_expect_u64(). */
static size_t count_in_log(const char *hay, const char *needle)
{
    size_t n = 0;

    if (hay == NULL) {
        return 0u;
    }
    for (const char *p = hay; *p != '\0';) {
        const char *hit = strstr(p, needle);

        if (hit == NULL) {
            break;
        }
        n++;
        p = hit + strlen(needle);
    }
    return n;
}

/* 333 RPL_TOPICWHOTIME: `:<server> 333 <client> <channel> <setter> <time> :<topic>`.
 *
 * PARSED, not searched, for the reason test_queries.c parses 317: every field can
 * be independently wrong while the code and the shape are right, and a substring
 * search for " 333 " is satisfied by a line carrying the code and nothing else.
 * The topic is read with a scanset rather than %s because it is free text and
 * contains spaces.
 *
 * The trailing topic is expected COLONNED, which the topic this file sets
 * guarantees (see TOPIC_TEXT): 3.2 colons a final parameter only when it needs
 * one, and a topic beginning with a space always does.
 *
 * No %s for the server name: %s WRITES to its argument and a string literal is
 * not a destination, so the prefix is stepped over with %*s instead.
 *
 * Returns 1 when a 333 was found in the window and all three fields parsed, and
 * 0 otherwise -- the caller reports which, because "there was no 333" and "the
 * 333 was malformed" are different faults.
 *
 * `setter` must have room for 128 bytes and `topic` for 512, which is what the
 * format's own widths assume; a smaller buffer is refused rather than written,
 * because the widths below are constants and a caller that passed something
 * smaller would have a buffer overflow with no diagnostic. The check is here
 * rather than documented and trusted because a test that silently corrupts its
 * own stack is worse than one that fails. */
static int read_333(const client_t *cl, size_t from, size_t end, char *setter,
                    size_t setter_cap, unsigned long long *when, char *topic,
                    size_t topic_cap)
{
    const char *base = tc_buffer(&cl->c);
    const char *at;
    const char *line_end;
    char wire[1024];
    size_t n;

    if (setter == NULL || topic == NULL || when == NULL || setter_cap < 128u ||
        topic_cap < 512u) {
        return 0;
    }
    at = strstr(base + from, ":" BIN_NAME " 333 ");
    if (at == NULL || at >= base + end) {
        return 0;
    }
    line_end = strstr(at, "\r\n");
    if (line_end == NULL || line_end > base + end) {
        return 0;
    }
    n = (size_t)(line_end - at);
    if (n >= sizeof wire) {
        n = sizeof wire - 1u;
    }
    memcpy(wire, at, n);
    wire[n] = '\0';
    /* The two %*s before the setter are <client> and <channel>; a 333 missing
     * either of them would shift the fields and the scanset would read the wrong
     * thing as the setter, which is a different bug from a malformed 333 and
     * shows up as a nonsense setter rather than as a parse failure. */
    return sscanf(wire, "%*s 333 %*s %*s %127s %31llu :%511[^\r\n]", setter, when,
                  topic) == 3;
}

int main(void)
{
    nf_node_t node;
    client_t alice, bob;
    size_t from, end;
    char want[512];
    char setter[128];
    char topic[512];
    unsigned long long when = 0;
    unsigned long long when_set = 0;
    size_t disposed;

    if (nf_spawn_binary(&node) != 0) {
        fprintf(stderr, "could not spawn the irc-serve binary\n");
        return 1;
    }
    TF_CHECK_MSG(nf_expect(&node, "loop_running:", T_READY_MS) == 0,
                 "the node never reported its loop armed");

    client_open(&alice, &node, "alice");
    client_open(&bob, &node, "bob");
    client_join(&alice, CHAN);
    client_join(&bob, CHAN);

    /* =======================================================================
     * 1. alice sets the topic, and 333 names HER as the setter
     * ==================================================================== */
    /* bob's window is opened FIRST: a window is a range of one client's buffer,
     * so a mark taken after the command would start past the reply the test is
     * looking for. */
    from = mark(&alice);
    {
        size_t bob_from = mark(&bob);

        TF_CHECK_MSG(tc_send(&alice.c, "TOPIC " CHAN " :" TOPIC_TEXT) == 0,
                     "tc_send failed");
        end = mark(&alice);
        settle_log(&node);
        /* 332 is `:<server> 332 <client> <channel> :<topic>` -- the channel is a
         * MIDDLE parameter and the topic the trailing one, which is why the needle
         * reads as it does. The setter is told the topic back, which is how it
         * learns the canonical form. */
        (void)snprintf(want, sizeof want,
                       ":" BIN_NAME " 332 alice #PERSIST :" TOPIC_TEXT "\r\n");
        expect_in_window(&alice, from, end, "332 for the setter", want);
        /* The time the setter's OWN 333 carries, kept so section 3 can require the
         * restored 333 to carry the SAME number. Checking only that it is
         * plausible -- non-zero, not in the future -- is not enough, and the
         * reason is a fault this file actually has teeth for: a cache that
         * restored the text and re-stamped topic_when with the current clock
         * would produce a 333 that passes every plausibility check and says the
         * topic was set at the moment of the rejoin. See section 3. */
        TF_CHECK_MSG(read_333(&alice, from, end, setter, sizeof setter, &when_set,
                              topic, sizeof topic) == 1,
                     "the setter's own 333 was missing or malformed, so there is "
                     "no baseline to compare the restored one against");
        TF_CHECK_MSG(strcmp(setter, "alice") == 0,
                     "the setter's own 333 names \"%s\" as the setter", setter);
        /* bob did NOT get a 332, and that is the node's design rather than an
         * omission: setting a topic is a state change, so the whole channel gets
         * the TOPIC line and the SETTER alone gets 332/333. Asserted as a
         * negative because a node that answered 332 to every member would look
         * like a friendlier implementation and would break a client that
         * distinguishes "what the channel is saying" from "what I just did". */
        {
            size_t bob_end = mark(&bob);
            char s2[128];
            char t2[512];
            unsigned long long w2 = 0;

            (void)snprintf(want, sizeof want,
                           ":alice!alice@" OBSERVED_HOST " TOPIC #PERSIST :"
                           TOPIC_TEXT "\r\n");
            expect_in_window(&bob, bob_from, bob_end,
                             "the TOPIC broadcast reaches the other member", want);
            expect_absent_in_window(&bob, bob_from, bob_end,
                                    "the other member's window for a topic set",
                                    " 332 ");
            expect_absent_in_window(&bob, bob_from, bob_end,
                                    "the other member's window for a topic set",
                                    " 333 ");
            /* bob is the client whose socket the SETTER is not, and he has to ask
             * for it: a QUERY is what gives him 332/333, and the 333 he gets must
             * still name alice. A node that stamped 333 with the recipient would
             * satisfy every assertion alice's socket can make. */
            from = mark(&bob);
            TF_CHECK_MSG(tc_send(&bob.c, "TOPIC " CHAN) == 0, "query send failed");
            end = mark(&bob);
            settle_log(&node);
            (void)snprintf(want, sizeof want,
                           ":" BIN_NAME " 332 bob #PERSIST :" TOPIC_TEXT "\r\n");
            expect_in_window(&bob, from, end, "332 for a query from another member",
                             want);
            TF_CHECK_MSG(read_333(&bob, from, end, s2, sizeof s2, &w2, t2,
                                  sizeof t2) == 1,
                         "bob's 333 was missing or malformed: the setter and the "
                         "time are the only record of who set the topic");
            TF_CHECK_MSG(strcmp(s2, "alice") == 0,
                         "333's <setter> for bob is \"%s\", expected \"alice\"", s2);
            TF_CHECK_MSG(strcmp(t2, TOPIC_TEXT) == 0,
                         "333's trailing topic for bob is \"%s\", expected \""
                         TOPIC_TEXT "\"",
                         t2);
        }
    }

    /* =======================================================================
     * 2. EVERYBODY GOES, and the channel is disposed
     * =======================================================================
     * This is the section the whole feature turns on, and getting it wrong is
     * easy: a channel with ONE member left is NOT disposed, so a test that
     * dropped only one client would see the topic come back from the LIVE
     * channel and would pass while testing nothing. The disposal is therefore
     * WAITED ON, and both ends of the channel leave -- alice by DROPPING (no
     * QUIT, no PART: the socket simply ends, which is the ordinary end of a TCP
     * connection and what a "reconnect" means nine times out of ten) and bob by
     * QUIT.
     *
     * The waits are on the node's own lines rather than on counters, for the
     * reason test_serverinfo.c gives: loop_stats is republished on the node's own
     * schedule and is published at shutdown, so a counter read here would be a
     * different wait with a different failure mode. */
    /* Let at least one wall-clock SECOND go by before the channel is disposed, so
     * that a restore which re-stamps topic_when with the current clock produces a
     * DIFFERENT number from the one the setter's 333 carried -- and the
     * comparison in section 3 becomes an assertion rather than a tautology. See
     * wait_second_advances() for why this is a fault that was otherwise
     * invisible. */
    TF_CHECK_MSG(wait_second_advances(&alice, when_set, T_IO_MS) != 0u,
                 "the wall-clock second did not advance within %d ms, so the "
                 "restored 333's <time> cannot be distinguished from a re-stamped "
                 "one and the assertion below is vacuous",
                 T_IO_MS);
    /* The clock really did move, stated so a reader can see the premise the next
     * section's comparison rests on. */
    TF_CHECK_MSG((unsigned long long)time(NULL) > when_set,
                 "the wall clock did not advance past %llu, so the restored "
                 "333's <time> comparison below proves nothing",
                 when_set);

    tc_close(&alice.c);
    TF_CHECK_MSG(nf_expect_nth(&node, "conn_reaped:", 1, T_IO_MS) == 0,
                 "the node did not notice alice's connection going away");
    TF_CHECK_MSG(tc_send(&bob.c, "QUIT :leaving") == 0, "QUIT send failed");
    TF_CHECK_MSG(nf_expect_nth(&node, "conn_reaped:", 2, T_IO_MS) == 0,
                 "the node did not notice bob's QUIT");
    /* A QUIT closes the far end; it does not free THIS side. tc_close() owns
     * c->buf, so a client that is opened and never tc_close()d leaks its whole
     * receive buffer. LeakSanitizer runs on the Linux CI job and caught exactly
     * this -- one 4096-byte realloc, from alice's registration read in the first
     * case, freed in the second. macOS cannot see it: LSan does not run on Darwin,
     * which is why this reached the CI job at all. */
    tc_close(&bob.c);
    TF_CHECK_MSG(nf_expect(&node, "chan_destroy: channel=#PERSIST", T_IO_MS) == 0,
                 "the node did not dispose #PERSIST, so its topic never had to "
                 "survive anything");
    /* And the cache was written on the way down. The wire assertions in section 3
     * are what pin the behaviour; this is here so a failure says WHICH half
     * broke rather than only what the symptom was. */
    TF_CHECK_MSG(nf_expect(&node, "topic_persist: channel=#PERSIST "
                                  "state=remembered",
                           T_IO_MS) == 0,
                 "the node disposed #PERSIST without remembering its topic");

    /* alice takes the same nickname again, which is only possible because the
     * reaper released it (issue #102). If it were still held this registration
     * would be a 433, and every assertion in section 3 would be about a different
     * connection than the one that set the topic. */
    client_open(&alice, &node, "alice");
    client_join(&alice, CHAN);

    /* =======================================================================
     * 3. THE ASSERTION: the topic is still there, and 333 still names alice
     * =======================================================================
     * The fresh socket's whole buffer is a valid window: it holds the welcome
     * burst and exactly one JOIN's worth of numerics, and there is no earlier 332
     * on it for a substring search to match by mistake. The channel was disposed
     * two steps ago, so what follows came from the cache and from nothing else. */
    (void)snprintf(want, sizeof want,
                   ":" BIN_NAME " 332 alice #PERSIST :" TOPIC_TEXT "\r\n");
    TF_CHECK_MSG(strstr(tc_buffer(&alice.c), want) != NULL,
                 "the topic did NOT survive the channel being disposed and "
                 "recreated: the exact 332 line is absent from alice's rejoin");
    /* 331 must be absent. A node that answered both 331 and 332 would satisfy
     * every positive assertion in this file. */
    expect_absent_in_window(&alice, 0, tc_received(&alice.c), "the restored topic",
                            " 331 ");
    TF_CHECK_MSG(read_333(&alice, 0, tc_received(&alice.c), setter, sizeof setter,
                          &when, topic, sizeof topic) == 1,
                 "no well-formed 333 for the restored topic, so the setter and the "
                 "time were not carried across the dispose");
    TF_CHECK_MSG(strcmp(setter, "alice") == 0,
                 "333's <setter> is \"%s\", expected \"alice\": the topic's author "
                 "did not survive the dispose",
                 setter);
    TF_CHECK_MSG(when > 1000000000ull,
                 "333's <time> is %llu, which is not a plausible Unix timestamp: "
                 "the topic was restored with no time",
                 when);
    TF_CHECK_MSG(when <= (unsigned long long)time(NULL),
                 "333's <time> is in the future");
    /* THE SAME NUMBER, and this is the assertion the two checks above cannot
     * make. 333's <time> is when the topic was set, and a restore that stamped
     * it with the current clock would produce a number that is plausible, in the
     * past, and wrong -- telling every client that reads it that the topic was
     * set at the moment of the rejoin, by the user who rejoined. The baseline is
     * the setter's own 333, read in section 1 before anything was disposed. */
    TF_CHECK_MSG(when == when_set,
                 "333's <time> after the restore is %llu but the setter's own 333 "
                 "said %llu: the topic's set time did not survive the dispose",
                 when, when_set);
    TF_CHECK_MSG(strcmp(topic, TOPIC_TEXT) == 0,
                 "333's trailing topic is \"%s\", expected \"" TOPIC_TEXT "\"",
                 topic);

    /* =======================================================================
     * 4. The topic is the CHANNEL's, not the setter's
     * =======================================================================
     * bob comes back, sets nothing, and is answered with the topic on his own
     * JOIN. This is the case that separates "the topic is remembered" from "the
     * connection that set it remembers something", and a cache keyed by the
     * setter would fail it. A test in which the setter is always the rejoiner
     * cannot tell those two apart at all, which is why the setter here is absent
     * from the channel and only appears as a string in 333. */
    client_open(&bob, &node, "bob");
    client_join(&bob, CHAN);
    (void)snprintf(want, sizeof want,
                   ":" BIN_NAME " 332 bob #PERSIST :" TOPIC_TEXT "\r\n");
    TF_CHECK_MSG(strstr(tc_buffer(&bob.c), want) != NULL,
                 "bob -- who was not on the channel when it was disposed, and who "
                 "has set nothing -- does not see the channel's topic");
    TF_CHECK_MSG(read_333(&bob, 0, tc_received(&bob.c), setter, sizeof setter,
                          &when, topic, sizeof topic) == 1,
                 "bob's JOIN produced no well-formed 333");
    TF_CHECK_MSG(strcmp(setter, "alice") == 0,
                 "333's <setter> as seen by a client that set nothing is \"%s\", "
                 "expected \"alice\"",
                 setter);

    /* =======================================================================
     * 5. A repeat JOIN, and a PART/re-JOIN while another member remains
     * =======================================================================
     * A repeat JOIN is answered with the topic, the roster and 366, and it must
     * not lose the topic. This is the case that needs a WINDOW: the same 332 is
     * already in alice's buffer from section 3, so a bare tc_expect() would match
     * the old copy and return instantly. */
    from = mark(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "JOIN " CHAN) == 0, "tc_send failed");
    end = mark(&alice);
    settle_log(&node);
    (void)snprintf(want, sizeof want,
                   ":" BIN_NAME " 332 alice #PERSIST :" TOPIC_TEXT "\r\n");
    expect_in_window(&alice, from, end, "332 for a repeat JOIN", want);
    TF_CHECK_MSG(read_333(&alice, from, end, setter, sizeof setter, &when, topic,
                          sizeof topic) == 1,
                 "no well-formed 333 for the repeat JOIN");
    TF_CHECK_MSG(strcmp(setter, "alice") == 0,
                 "333's <setter> became \"%s\" after a repeat JOIN", setter);

    /* A PART with bob still on the channel does NOT go through the cache at all:
     * the channel survives, and the topic is the live channel's. Asserted because
     * it distinguishes the two paths -- if the topic only ever came back from the
     * cache, this case would pass even with the channel never disposed. */
    from = mark(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "PART " CHAN) == 0, "PART send failed");
    end = mark(&alice);
    settle_log(&node);
    /* The departure is confirmed by its OWN echo, not by a 366: 366 is the
     * terminator of a NAMES list and a PART does not send one, so an assertion
     * here would be about a numeric this verb never produces. */
    TF_CHECK_MSG(strstr(tc_buffer(&alice.c) + from,
                        ":alice!alice@" OBSERVED_HOST " PART #PERSIST") != NULL &&
                     strstr(tc_buffer(&alice.c) + from,
                            ":alice!alice@" OBSERVED_HOST " PART #PERSIST") <
                         tc_buffer(&alice.c) + end,
                 "alice's PART was not echoed to her inside the window");
    /* And a PART narrates no topic at all. A 332 in this window would be the node
     * reporting state the client did not ask about. */
    expect_absent_in_window(&alice, from, end, "the PART window", " 332 ");
    /* The channel must NOT have been disposed: bob is still on it. The count is
     * asserted rather than the absence of a line, because nf_expect() can only
     * assert that something IS present -- there is no helper for "has not
     * happened yet", which is the same reason count_in_log() exists above. */
    TF_CHECK_MSG(count_in_log(node.out, "chan_destroy: channel=#PERSIST") == 1u,
                 "#PERSIST was disposed %zu time(s) after a PART with bob still "
                 "on it, expected 1: a channel with a member must survive",
                 count_in_log(node.out, "chan_destroy: channel=#PERSIST"));

    from = mark(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "JOIN " CHAN) == 0, "re-JOIN send failed");
    end = mark(&alice);
    settle_log(&node);
    (void)snprintf(want, sizeof want,
                   ":" BIN_NAME " 332 alice #PERSIST :" TOPIC_TEXT "\r\n");
    expect_in_window(&alice, from, end, "332 after a PART and re-JOIN", want);

    /* =======================================================================
     * 6. A topic that is CLEARED must not come back
     * =======================================================================
     * `TOPIC #chan :` is one empty trailing parameter and it removes the topic
     * (chan_set_topic()). The cache's job here is to FORGET: a cache that
     * remembered the old text would put back a topic the user deliberately
     * removed, and the only way to spell "remembered but empty" without a second
     * state is not to store it at all. */
    from = mark(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "TOPIC " CHAN " :") == 0, "tc_send failed");
    end = mark(&alice);
    settle_log(&node);
    expect_in_window(&alice, from, end, "331 after clearing the topic",
                     ":" BIN_NAME " 331 alice #PERSIST :No topic is set\r\n");
    expect_absent_in_window(&alice, from, end, "the cleared topic", " 332 ");

    /* Everybody out, so the channel is disposed again -- the second dispose, and
     * this one carries a channel whose topic is now empty. */
    TF_CHECK_MSG(tc_send(&alice.c, "PART " CHAN) == 0, "PART send failed");
    TF_CHECK_MSG(tc_send(&bob.c, "PART " CHAN) == 0, "PART send failed");
    TF_CHECK_MSG(nf_expect_nth(&node, "chan_destroy: channel=#PERSIST", 2, T_IO_MS)
                     == 0,
                 "the node did not dispose #PERSIST a second time");
    TF_CHECK_MSG(nf_expect(&node, "topic_persist: channel=#PERSIST "
                                  "state=forgotten",
                           T_IO_MS) == 0,
                 "the node disposed a channel whose topic had been CLEARED "
                 "without forgetting the old one, so the next JOIN could restore a "
                 "topic the user removed");
    from = mark(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "JOIN " CHAN) == 0, "re-JOIN send failed");
    end = mark(&alice);
    settle_log(&node);
    expect_in_window(&alice, from, end, "331 for a topic the user CLEARED",
                     ":" BIN_NAME " 331 alice #PERSIST :No topic is set\r\n");
    expect_absent_in_window(&alice, from, end, "the cleared topic", " 332 ");

    /* =======================================================================
     * 7. A channel nobody ever gave a topic still answers 331 after a dispose
     * =======================================================================
     * The negative for the cache itself: a channel that never had a topic must
     * not acquire one on the way through, and a cache that invented an entry
     * would satisfy every positive assertion in this file. A DIFFERENT channel
     * name, so the wait cannot be satisfied by a #PERSIST dispose. */
    from = mark(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "JOIN " OTHER) == 0, "JOIN send failed");
    end = mark(&alice);
    settle_log(&node);
    expect_in_window(&alice, from, end, "331 on a brand new channel",
                     ":" BIN_NAME " 331 alice #OTHER :No topic is set\r\n");
    TF_CHECK_MSG(tc_send(&alice.c, "PART " OTHER) == 0, "PART send failed");
    TF_CHECK_MSG(nf_expect(&node, "chan_destroy: channel=#OTHER", T_IO_MS) == 0,
                 "the node did not dispose #OTHER");
    from = mark(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "JOIN " OTHER) == 0, "re-JOIN send failed");
    end = mark(&alice);
    settle_log(&node);
    expect_in_window(&alice, from, end, "331 for a channel that never had a topic",
                     ":" BIN_NAME " 331 alice #OTHER :No topic is set\r\n");
    expect_absent_in_window(&alice, from, end, "the untouched channel", " 332 ");

    /* =======================================================================
     * The node's own accounting
     * =======================================================================
     * The disposal COUNTS, and they are the only wire-visible way to tell the
     * cached path from the live one. This test empties #PERSIST twice -- once in
     * section 2 and once in section 6 -- and #OTHER once, and each empty is a
     * dispose. A PART that disposed a channel with a member still on it, or a
     * teardown that disposed a channel that was never empty, makes these wrong. */
    disposed = count_in_log(node.out, "chan_destroy: channel=#PERSIST");
    TF_CHECK_MSG(disposed == 2u,
                 "#PERSIST was disposed %zu time(s), expected exactly 2: a "
                 "channel with a member must not be disposed, and one that is "
                 "emptied must be",
                 disposed);
    TF_CHECK_MSG(count_in_log(node.out, "chan_destroy: channel=#OTHER") == 1u,
                 "#OTHER was disposed %zu time(s), expected exactly 1",
                 count_in_log(node.out, "chan_destroy: channel=#OTHER"));

    TF_CHECK_MSG(nf_stop(&node) == 0, "node did not exit cleanly");
    /* 0, and this is not a formality: "the topic survived" would also be true of a
     * node whose cache never filled because the channels were never disposed, and
     * this counter plus the disposer counts above are what rule that out. A
     * non-zero value here is a topic the node was asked to remember and could
     * not. */
    TF_CHECK_MSG(nf_expect_u64(&node, "topic_cache_full=", 0, T_IO_MS) == 0,
                 "topic_cache_full is not 0: the node lost a topic at the cache "
                 "bound, so the survivals above prove less than they appear to");
    TF_CHECK_MSG(nf_expect_u64(&node, "reply_refused=", 0, T_IO_MS) == 0,
                 "reply_refused is not 0");
    TF_CHECK_MSG(nf_expect_u64_ge(&node, "accepted=", g_opened, T_IO_MS) == 0,
                 "the node accepted fewer connections than the test opened (%zu)",
                 g_opened);

    tc_close(&alice.c);
    tc_close(&bob.c);
    nf_free(&node);
    tf_done("topic_persist");
    return 0;
}
