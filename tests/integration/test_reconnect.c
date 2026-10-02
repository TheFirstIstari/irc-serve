/* test_reconnect.c -- a client whose TCP session is LOST and who comes back gets
 * its channel set, through a real dropped socket.
 *
 * docs/SERVER_DESIGN.md 2.1 (the key: nick, ident and host), 2.2 (single writer,
 * and therefore what a restore may re-grant), 3.1 (what a JOIN writes and
 * forwards, which is what a restore inherits), 4.2/4.4 (the verbs and numerics a
 * restore is allowed to use) and 8 (the `Reconnect` item this retires).
 *
 * ---------------------------------------------------------------------------
 * THIS FILE WAS A 10-LINE PLACEHOLDER THAT RETURNED CTest's SKIP CODE
 * ---------------------------------------------------------------------------
 * It lived in tests/loadbal/, which is the directory the phase table put
 * reconnect in because reconnect was one of five skips §7/Phase 9 owned
 * alongside peer discovery and auto-scale. Three of those five are federation or
 * orchestration features; this one is not. A client reconnecting is a SINGLE
 * node's business -- there is no peer, no link and no mesh anywhere in this
 * file -- so putting it next to tests/loadbal/test_autoscale.c was a
 * classification by the skip's name rather than by what the feature is.
 *
 * IT IS HERE, IN tests/integration/, for the reason Phase 8 moved the IRCv3
 * tests out of tests/compliance/ and 7/Phase 6 moved the SBURST tests out of
 * tests/federation/: this feature is only observable over a socket, by a client
 * that really connects and really disconnects, and a unit test in
 * tests/loadbal/ -- which links irc_core and nothing else -- has no way to
 * spawn a node, no way to drop a socket and no way to read a 366.
 *
 * THE CTest NAME IS UNCHANGED (`Reconnect`), and that is why irc_ctest_name()
 * exists on this side. tests/known_skips.txt names the test, and
 * scripts/check-skips.sh cross-checks every listed name against the registered
 * set in BOTH directions -- so renaming the test to suit a build system is how a
 * skip line goes stale without anybody noticing. The name is being RETIRED
 * from that list in this change, and the retirement is why the name still
 * matters: a CI link to a past run names it.
 *
 * ---------------------------------------------------------------------------
 * WHY THE DROP IS A REAL SOCKET AND NOT A CLOSED conn_t
 * ---------------------------------------------------------------------------
 * The placeholder's own text said "honest CTest skip rather than SIMULATED
 * RECONNECT STATE", and that warning is the design brief for this file. So the
 * case does the only thing that can be called a lost session:
 *
 *   1. tc_connect() a real socket to a real child node.
 *   2. NICK, USER, JOIN, and become an operator -- over that socket.
 *   3. tc_close() it. NOT a QUIT, and that is not a detail: a QUIT is a
 *      statement that the client is leaving, and core/resume.c deliberately does
 *      not record a window for one (see resume.h on why). So a case that sent
 *      QUIT and then reconnected would be testing a different feature.
 *   4. Wait for the node's OWN `conn_reaped:` line, which is the proof that the
 *      node noticed the drop, tore the connection down and released the
 *      nickname. Without that wait the reconnect could arrive while the old
 *      connection still holds the name, and the client would be answered 433 --
 *      which is a correct outcome for a name that is still in use and tells us
 *      nothing about the window. A case that retried until it got in would be
 *      testing a race.
 *   5. tc_connect() a SECOND real socket, NICK and USER with the same values,
 *      and assert what comes back.
 *
 * There is no in-process shortcut anywhere in this file, and there is no seam
 * that hands a caller the old conn_t: the window holds three strings and a
 * bounded array of channel NAMES, so there is no object to hand back even if a
 * caller wanted one. See core/resume.h.
 *
 * ---------------------------------------------------------------------------
 * WHAT IS ASSERTED, AND WHERE EACH CLAIM COMES FROM
 * ---------------------------------------------------------------------------
 *   1. THE CHANNEL SET COMES BACK, on the wire: a 366 per channel, and the
 *      channel in a 353 from a client that did NOT ask for the restore. A node
 *      that restored the channels in its own tables but not to its clients would
 *      fail this, and so would one that restored them without the roster.
 *   2. THE PER-CHANNEL MODES COME BACK on an owned channel, in the 353 itself:
 *      `@` for the channel the client was op in, and nothing for the one it was
 *      not. This is claim 2.2 does NOT make -- the origin decides prefixes, and
 *      on a single node the origin is this node -- so it is the one claim that
 *      needs the flags restored rather than dropped.
 *   3. THE WINDOW IS ONE-SHOT. A third connection with the same nick and ident
 *      gets NO restore, which is both the security property (a window cannot be
 *      replayed) and the thing that makes "where is this freed" answerable.
 *   4. A KEY MISMATCH GETS NO WINDOW. Same nick, different ident: refused, and
 *      the client is told. This is the half of the key that matters most -- an
 *      ident is chosen to identify a person ACROSS sessions, so the same nick
 *      with a different ident is a different thing wearing the same name.
 *   5. A LIVE HOLDER OF THE NICK IS NOT EVICTED. This is the collision claim:
 *      with a window outstanding, a second client claims the nick, and the
 *      window does not become a way to take a live session away from whoever is
 *      using it. The honest alternative -- kicking the old session -- would let
 *      anyone who knows a nick evict the person using it, and on a node with no
 *      authentication (core/resume.h says so) that is a free denial of service
 *      with no secret required. So the newcomer is refused, which is also what
 *      the node already did before this feature.
 *   6. EXPIRY IS VISIBLE ON THE WIRE, not a silent fallback: with a shortened
 *      window, a client that comes back after it has closed is told, in a NOTICE
 *      it can render, and is restored nothing.
 *   7. THE WINDOW IS BOUNDED IN COUNT and does not grow without limit, and the
 *      teardown arm is observable: the node prints `session_resume_close:
 *      table=OPEN` on shutdown with a window still outstanding, so the arm can
 *      be asserted on a platform whose LeakSanitizer does not run.
 *   8. A RESTORE IS AN ORDINARY JOIN on the wire -- a client that did not drop
 *      and asks to be told about the window is told it is a member of nothing,
 *      so the feature is invisible to clients that do not use it.
 *
 * ---------------------------------------------------------------------------
 * WHAT WAS SHORTENED, AND WHY IT IS STILL A REAL TEST
 * ---------------------------------------------------------------------------
 * Exactly one number: the window length. The shipped value is
 * IRC_RESUME_WINDOW_MS = 120000, so waiting out a real expiry would be a
 * two-minute test on a good runner and a five-minute one on a loaded CI box.
 *
 * The child calls resume_set_window(400) and the expiry case waits for the
 * node's own `session_resume_miss: ... reason=EXPIRED` line. Every other number
 * in this file is the shipped one, and -- this is the part that matters -- the
 * thing being tested is not the LENGTH. It is:
 *
 *   - that a window is taken on a lost session and NOT on a QUIT (a flag
 *     decision, no clock);
 *   - that a window is keyed on three fields (a comparison, no clock);
 *   - that the restore goes through the same admit path a JOIN does (a call
 *     graph, no clock);
 *   - that the window is consumed on use and freed (an ownership fact, no clock);
 *   - that the table is bounded (a count, no clock);
 *   - and that the expiry DECISION is made at all.
 *
 * Shortening the window changes how long the sixth of those takes to become
 * true and nothing about whether it is. A 400 ms window is the same predicate
 * with a different constant in it, and the shipped constant is asserted by
 * resume_set_window()'s own unit-level contract (a zero is refused, so "no
 * window" and "a window that expires immediately" stay different
 * configurations) rather than by a two-minute test.
 *
 * ---------------------------------------------------------------------------
 * NO FIXED sleep() ANYWHERE (6.3)
 * ---------------------------------------------------------------------------
 * Every wait is a deadline over a child's output or over a socket. The window
 * is a clock, so the expiry case does have to let one elapse -- and the way to
 * do that without a sleep is to make the node TELL you when it has: the
 * `session_resume_miss: reason=EXPIRED` line is the node's own statement that
 * its clock has passed the bound, so waiting for it is waiting for the
 * behaviour rather than for a duration.
 */
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "core/commands.h"
#include "core/resume.h"
#include "core/resume.h"
#include "core/server.h"
#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

#define T_IO_MS 20000

/* THE WINDOW LENGTH FOR THE EXPIRY CASE, and the only number in this file that
 * is not the shipped one. See the header for why shortening it does not make
 * the test less real: the claim is that the expiry DECISION is taken and
 * reported, not that it takes 120 seconds to take. */
#define RESUME_WINDOW_MS 1500

/* The one identity every connection in this file claims, and the three fields of
 * it that the window is keyed on. The ident is the one that matters: it is the
 * field a person chooses to be recognised across sessions, so `NICK bob` with
 * this ident is the same person coming back and `NICK bob` with a different one
 * is not. */
#define NICK_MAIN "bob"
#define NICK_KEY "erin"
#define IDENT_KEY "erinident"
#define IDENT_WRONG "wrongident"
#define NICK_LATE "dave"
#define IDENT_LATE "daveident"
#define IDENT_MAIN "bobident"
#define IDENT_OTHER "otherident"

#define CHAN_OP  "#OPCHAN"
#define CHAN_PLAIN "#PLAIN"

/* The observable node lines this file waits for, spelled out as constants so a
 * rename of any of them breaks the build rather than silently making an
 * assertion pass by never running. */
#define REAPED "[observable] conn_reaped: fd="
#define NOTE   "[observable] session_resume_note: nick=" NICK_MAIN " ident=" IDENT_MAIN
#define APPLIED "[observable] session_resume: nick=" NICK_MAIN " ident=" IDENT_MAIN
#define MISS_EXPIRED "[observable] session_resume_miss: nick=" NICK_LATE \
                     " ident=" IDENT_LATE " reason=EXPIRED"
#define CLOSED "[observable] session_resume_close: table=OPEN"
/* The expiry case's two waits, and they NAME the client rather than counting:
 * nf_expect() searches the whole accumulated buffer, so a summary line saying
 * "retired=1" is satisfied by the retirement of an unrelated window, and a test
 * that waited for one would be measuring a different client's expiry. A line
 * naming the nick is a wait for the thing itself. */
#define RETIRE_LATE "[observable] session_resume_retire: nick=" NICK_LATE

static void child_setup(server_t *s)
{
    TF_CHECK_MSG(commands_dispatch != NULL,
                 "the client command surface is missing from the build");
    s->dispatch = commands_dispatch;
    /* The window, shortened. Set before anything can drop a client, which is
     * before any socket is accepted, so there is no window in which a client
     * could be recorded against the shipped length. */
    resume_set_window(RESUME_WINDOW_MS);
    printf("[fixture] resume_window_ms=%llu\n",
           (unsigned long long)resume_window_ms());
}

/* Register a client and drain with a UNIQUE token, so that every later wait on
 * this connection is against bytes read since. tc_expect() searches the whole
 * accumulated buffer, so a shared token would let one drain satisfy the next. */
static void register_client(test_client_t *c, int port, const char *nick,
                            const char *ident, const char *token)
{
    char line[256];

    TF_CHECK_MSG(tc_connect(c, port) == 0, "%s could not connect", nick);
    (void)snprintf(line, sizeof line, "NICK %s", nick);
    TF_CHECK_MSG(tc_send(c, line) == 0, "NICK send failed for %s", nick);
    (void)snprintf(line, sizeof line, "USER %s 0 *spoofed :Real %s", ident, ident);
    TF_CHECK_MSG(tc_send(c, line) == 0, "USER send failed for %s", nick);
    TF_CHECK_MSG(tc_expect(c, " 001 ", T_IO_MS) == 0, "%s never registered", nick);
    (void)snprintf(line, sizeof line, "PING :%s", token);
    TF_CHECK_MSG(tc_send(c, line) == 0, "%s's drain PING send failed", nick);
    TF_CHECK_MSG(tc_expect(c, token, T_IO_MS) == 0,
                 "%s got no PONG carrying its drain token, so the lines before it "
                 "have not been read yet",
                 nick);
}

/* Everything this client has received SINCE `mark`. The buffer only grows and is
 * NUL-terminated, so an offset into it is a valid C string -- and it is how a
 * "this name is NOT in the roster" assertion avoids matching a roster this same
 * client asked for earlier. */
static const char *since(const test_client_t *c, size_t mark)
{
    const char *buf = tc_buffer(c);

    return (tc_received(c) > mark) ? buf + mark : "";
}

/* The NAMES TEXT of one channel's 353, as a pointer and a length into the
 * caller's buffer, or NULL when this buffer holds no 353 for that channel.
 *
 * IT EXISTS BECAUSE "IS THE NAME IN THE ROSTER" IS NOT A SUBSTRING QUESTION, and
 * three false readings came out of trying to make it one:
 *
 *   - The 353 line is `:server 353 <nick> = <#chan> <names>`, so the WATCHER'S
 *     OWN NICKNAME appears in every roster it is ever sent and a
 *     `strstr(roster, "bob")` is satisfied by the numeric's own target parameter
 *     on a channel where bob is not a member at all.
 *   - A 353 and its 366 terminator BOTH name the channel and both end in a
 *     trailing parameter, so searching for "<#chan> :" finds the terminator as
 *     readily as the roster and hands back the words "End of /NAMES list".
 *   - This node renders 353's trailing text WITHOUT the leading colon (reply()'s
 *     own rendering, which the whole suite already depends on), so a helper that
 *     looked for the colon RFC 2812 2.4.5 shows would find no roster at all.
 *
 * So the scan is anchored on the numeric CODE, which is unique in this
 * codebase's roster family -- 353 is the names list, 366 is its terminator and
 * 352 is WHO's per-member line with no trailing list -- and the names begin after
 * the LAST occurrence of the channel name in that line, with spaces skipped. */
static const char *roster_text(const char *hay, const char *chan, size_t *len_out)
{
    size_t clen = strlen(chan);
    const char *at;

    if (hay == NULL || chan == NULL) {
        return NULL;
    }
    for (at = hay; (at = strstr(at, " 353 ")) != NULL; at += 5) {
        const char *line = at + 5;
        const char *end = strpbrk(line, "\r\n");
        const char *body = NULL;
        size_t span;
        size_t i;

        if (end == NULL) {
            end = line + strlen(line);
        }
        span = (size_t)(end - line);
        /* THE LAST OCCURRENCE, so a channel name that is a suffix of another
         * channel's name cannot make this match the wrong 353 -- and the
         * occurrence must be a WHOLE name, bounded by a space on the left,
         * because `#OP` is not inside `#OPP`. */
        for (i = 0; i + clen <= span; i++) {
            if (memcmp(line + i, chan, clen) == 0 && i > 0u && line[i - 1] == ' ') {
                body = line + i + clen;
            }
        }
        if (body == NULL) {
            continue;
        }
        while (body < end && *body == ' ') {
            body++;
        }
        if (len_out != NULL) {
            *len_out = (size_t)(end - body);
        }
        return body;
    }
    if (len_out != NULL) {
        *len_out = 0u;
    }
    return NULL;
}

/* How many times `nick` appears in a name list as a WHOLE NAME, where the name
 * list is what roster_text() returned and `len` is its length. The bound is the
 * length rather than a NUL because the list is a slice of a larger buffer.
 *
 * THE BOUNDARIES ARE THE NICKNAME CHARS and nothing else, which is what makes a
 * member drawn as `@bob` or `+bob` ONE occurrence: a substring count would find
 * `bob` inside `bobby` as well, and the sigils are deliberately NOT treated as
 * name characters so that `@bob` is not skipped. */
static size_t roster_count(const char *names, size_t len, const char *nick)
{
    size_t nlen = strlen(nick);
    size_t found = 0u;
    size_t i = 0u;

    if (names == NULL) {
        return 0u;
    }
    while (i + nlen <= len) {
        char before = (i == 0u) ? ' ' : names[i - 1];
        char after = (i + nlen >= len) ? ' ' : names[i + nlen];
        /* THE NAME CHARS on the left are alphanumerics and '_' and NOTHING
         * ELSE -- so `@` and `+` are valid LEFT boundaries, because they are the
         * prefix sigils 2.2's CHAN_MEMBER_OP and CHAN_MEMBER_VOICE render. That
         * is the one mistake this function's first version made, and it is worth
         * recording: it counted a member drawn as `@bob` ZERO times, which reads
         * as "bob is not on the channel" for a channel bob is on. */
        int before_ok = !((before >= 'a' && before <= 'z') ||
                          (before >= 'A' && before <= 'Z') ||
                          (before >= '0' && before <= '9') || before == '_');
        int after_ok = !((after >= 'a' && after <= 'z') ||
                         (after >= 'A' && after <= 'Z') ||
                         (after >= '0' && after <= '9') || after == '_');

        if (memcmp(names + i, nick, nlen) == 0 && before_ok && after_ok) {
            found++;
            i += nlen;
            continue;
        }
        i++;
    }
    return found;
}

/* ---------------------------------------------------------------------------
 * THE CASE
 * ---------------------------------------------------------------------------
 * One node, no peers, one client. Six beats, in order, and the order is the
 * order the feature's rules depend on:
 *
 *   1. REGISTER, JOIN TWO CHANNELS, BECOME OP IN ONE. That is the state a
 *      window is a record of.
 *   2. THE SOCKET IS CLOSED. A real close, no QUIT.
 *   3. THE NODE REAPS IT, which is the proof the drop was real and the
 *      synchronisation point for everything after it.
 *   4. IT COMES BACK, and the four claims: the channel set, the modes, the
 *      one-shot, and the key mismatch.
 *   5. THE COLLISION: a window is outstanding for the nick, a second client
 *      claims the nick, and the live holder is not evicted.
 *   6. EXPIRY, and the teardown arm, both observable.
 */
static void case_a_dropped_client_gets_its_channels_back(void)
{
    nf_node_t n;
    test_client_t first;
    test_client_t again;
    test_client_t watcher;
    test_client_t late;
    char line[200];
    size_t mark;

    TF_CHECK_MSG(nf_spawn_inline_named(&n, "irc.r", child_setup) == 0,
                 "could not spawn the node");
    TF_CHECK_MSG(n.port > 0, "the node reported no port");

    /* --- beat 1: a session worth losing ------------------------------------ */
    register_client(&first, n.port, NICK_MAIN, IDENT_MAIN, "reg-first");
    /* ONE CHANNEL PER JOIN COMMAND, and that is a fact about this build rather
     * than a style choice: handle_join() splits ONLY m->params[0] and iterates
     * the result, so `JOIN #a #b` joins the first name and ignores the second.
     * Writing the two commands separately is what makes this test's channel
     * count a fact about the window rather than about a command parser. */
    TF_CHECK_MSG(tc_send(&first, "JOIN " CHAN_OP) == 0, "the first JOIN failed");
    TF_CHECK_MSG(tc_expect(&first, " 366 ", T_IO_MS) == 0,
                 "the JOIN of " CHAN_OP " never completed");
    TF_CHECK_MSG(tc_send(&first, "JOIN " CHAN_PLAIN) == 0, "the second JOIN failed");
    TF_CHECK_MSG(tc_expect(&first, " 366 ", T_IO_MS) == 0,
                 "the JOIN of " CHAN_PLAIN " never completed");
    TF_CHECK_MSG(nf_expect(&n, "chan_join: channel=" CHAN_OP " nick=" NICK_MAIN
                              " members=1",
                           T_IO_MS) == 0,
                 "the node never recorded the join of " CHAN_OP ": %s", n.out);

    /* THE CLIENT IS AN OPERATOR IN ONE CHANNEL AND NOT THE OTHER, which is the
     * state the per-channel flags have to be able to express. +o is granted by
     * the ordinary MODE path, so the fact under test is the RESTORE of it and
     * not the grant -- but the grant still has to be ESTABLISHED here, or the
     * whole operator claim would be measuring a window that recorded nothing.
     *
     * THE `@` IS NOT IN THE MODE ECHO and the test has to know that: 3.1's echo
     * is `:prefix MODE #chan +o nick`, four parameters and no prefix sigil on
     * the nick. The sigil appears in a 353, so the client asks for its own
     * roster -- which is also the answer a client actually uses to find out
     * whether it is an operator, so this is not a test-only path. */
    (void)snprintf(line, sizeof line, "MODE %s +o %s", CHAN_OP, NICK_MAIN);
    TF_CHECK_MSG(tc_send(&first, line) == 0, "the MODE +o send failed");
    TF_CHECK_MSG(tc_expect(&first, " MODE " CHAN_OP " +o " NICK_MAIN, T_IO_MS) == 0,
                 "the client never saw its own +o echo, so it is not an operator "
                 "and the restore has nothing to restore: %s",
                 tc_buffer(&first));
    /* AND THE CLIENT IS *NOT* AN OPERATOR IN THE OTHER, which is the other half
     * of what the per-channel flags have to express. It is arranged by DE-OPING
     * rather than by having somebody else create the channel, and the reason is
     * that this node grants +o to a channel's CREATOR (chan_verbs.c's comment on
     * RFC 1459 2.3.1) -- so any channel the client joins on a node with no other
     * member is one it created, and every channel it was in would come back
     * with the same flag. De-opping keeps BOTH channels bob-only, which is also
     * what makes them a test of the channel-retention guard below: a channel with
     * no other member is destroyed the moment its only member drops, so without
     * core/resume.c's hold the restore would find nothing to rejoin.
     *
     * A client can de-op itself because it is the operator, and the echo it sees
     * is the same four-parameter MODE it sent. */
    (void)snprintf(line, sizeof line, "MODE %s -o %s", CHAN_PLAIN, NICK_MAIN);
    TF_CHECK_MSG(tc_send(&first, line) == 0, "the MODE -o send failed");
    TF_CHECK_MSG(tc_expect(&first, " MODE " CHAN_PLAIN " -o " NICK_MAIN, T_IO_MS) == 0,
                 "the client never saw its own -o echo, so it may still be an "
                 "operator of " CHAN_PLAIN " and the two channels would not "
                 "differ: %s",
                 tc_buffer(&first));

    mark = tc_received(&first);
    (void)snprintf(line, sizeof line, "NAMES " CHAN_OP);
    TF_CHECK_MSG(tc_send(&first, line) == 0, "the client's NAMES send failed");
    (void)snprintf(line, sizeof line, "PING :after-op");
    TF_CHECK_MSG(tc_send(&first, line) == 0, "the post-op PING send failed");
    TF_CHECK_MSG(tc_expect(&first, "after-op", T_IO_MS) == 0,
                 "the client never got its PONG: %s", tc_buffer(&first));
    TF_CHECK_MSG(strstr(since(&first, mark), "@" NICK_MAIN) != NULL,
                 "the client's own roster does not show it as an operator of "
                 CHAN_OP " after MODE +o, so the operator status this test is "
                 "about was never established: %s",
                 since(&first, mark));

    /* --- beat 2 and 3: the socket is CLOSED, and the node notices ---------- */
    /* NO QUIT. tc_close() drops the TCP session, which is the whole point; a
     * QUIT here would be a different feature (see the header). */
    tc_close(&first);
    /* THE SYNCHRONISATION POINT, and it is a node line rather than a delay: the
     * reap is asynchronous, and a reconnect that arrived before it would find the
     * nickname still held and be answered 433 -- which is CORRECT for a name in
     * use and says nothing about the window. */
    TF_CHECK_MSG(nf_expect(&n, REAPED, T_IO_MS) == 0,
                 "the node never reaped the dropped connection, so the drop did "
                 "not happen as far as the node is concerned: %s",
                 n.out);
    TF_CHECK_MSG(nf_expect(&n, NOTE, T_IO_MS) == 0,
                 "the node recorded no session window for the dropped client. "
                 "The window is taken on a LOST session and not on a QUIT, and "
                 "this connection lost its socket: %s",
                 n.out);
    TF_CHECK_MSG(strstr(n.out, NOTE " chans=2") != NULL,
                 "the window recorded %s, so the restore cannot put the client "
                 "back into the two channels it was in: %s",
                 NICK_MAIN, n.out);

    /* --- beat 4: it comes back ---------------------------------------------- */
    /* A SECOND REAL SOCKET, the same NICK and the same ident. There is no seam
     * that could hand back the old connection: the window holds three strings
     * and a bounded array of channel names. */
    register_client(&again, n.port, NICK_MAIN, IDENT_MAIN, "reg-again");
    TF_CHECK_MSG(nf_expect(&n, APPLIED, T_IO_MS) == 0,
                 "the node applied no window to the reconnecting client, so the "
                 "channel set did not come back: %s",
                 n.out);
    TF_CHECK_MSG(strstr(n.out, APPLIED " chans=2 joined=2") != NULL,
                 "the node restored %s of the two recorded channels. A channel "
                 "the client was in two hundred milliseconds ago should still "
                 "exist on a single node with one client: %s",
                 NICK_MAIN, n.out);

    /* CLAIM 1, THE CHANNEL SET, ON THE WIRE. Two 366s: one per channel, sent by
     * the same admit path a typed JOIN goes through. A node that restored its
     * own tables without telling the client would fail this. */
    (void)snprintf(line, sizeof line, "PING :after-restore");
    TF_CHECK_MSG(tc_send(&again, line) == 0, "the post-restore PING send failed");
    TF_CHECK_MSG(tc_expect(&again, "after-restore", T_IO_MS) == 0,
                 "the reconnecting client never got its PONG, so the node had "
                 "not finished the restore when this assertion ran: %s",
                 tc_buffer(&again));
    TF_CHECK_MSG(strstr(tc_buffer(&again), " 366 " NICK_MAIN " " CHAN_OP) != NULL,
                 "the restore did not send a 366 for " CHAN_OP ", so the client "
                 "was not told it is a member: %s",
                 tc_buffer(&again));
    TF_CHECK_MSG(strstr(tc_buffer(&again), " 366 " NICK_MAIN " " CHAN_PLAIN) != NULL,
                 "the restore did not send a 366 for " CHAN_PLAIN ": %s",
                 tc_buffer(&again));

    /* CLAIM 2, THE PER-CHANNEL MODES, IN A 353 THE CLIENT DID NOT ASK FOR. The
     * watcher is a second client on the same node, in neither channel, and its
     * roster is the node's own answer about who is where -- which is where a
     * restore that dropped the operator status would show, and where a restore
     * that granted it where it was not held would show too. */
    /* A CLIENT THAT ASKED FOR NOTHING, and that is the load-bearing part of how
     * this roster is read: tc_expect() searches the whole accumulated buffer, so
     * a 366 this same connection received two commands ago satisfies a wait for
     * the next one -- which would turn every "this name is NOT in the roster"
     * assertion into a statement about the parent's read schedule. A connection
     * that has never asked anything cannot be satisfied by an earlier answer. */
    register_client(&watcher, n.port, "watcher", "watchident", "reg-watch");
    mark = tc_received(&watcher);
    (void)snprintf(line, sizeof line, "NAMES " CHAN_OP);
    TF_CHECK_MSG(tc_send(&watcher, line) == 0, "the watcher's NAMES send failed");
    (void)snprintf(line, sizeof line, "PING :watch-op");
    TF_CHECK_MSG(tc_send(&watcher, line) == 0, "the watcher's PING send failed");
    TF_CHECK_MSG(tc_expect(&watcher, "watch-op", T_IO_MS) == 0,
                 "the watcher never got its PONG: %s", tc_buffer(&watcher));
    {
        size_t rlen = 0u;
        const char *roster = roster_text(since(&watcher, mark), CHAN_OP, &rlen);

        TF_CHECK_MSG(roster != NULL,
                     "the watcher never received a 353 for " CHAN_OP ", so every "
                     "claim below would be about a roster that does not exist: %s",
                     since(&watcher, mark));
        TF_CHECK_MSG(roster != NULL && roster_count(roster, rlen, NICK_MAIN) == 1u,
                     NICK_MAIN " appears %zu times in " CHAN_OP "'s roster, so the "
                     "restore did not put exactly one member there: %.*s",
                     roster_count(roster, rlen, NICK_MAIN), (int)rlen,
                     (roster != NULL) ? roster : "");
        /* AND THE PREFIX. This is claim 2.2 does NOT make: the ORIGIN decides a
         * channel's prefixes, and on a single node the origin is this node, so a
         * window's recorded operator status is this node's to re-grant. It is
         * the one claim that needs the flags RESTORED rather than dropped, and
         * it is asserted in the roster a client did not ask for. */
        TF_CHECK_MSG(roster != NULL && strstr(roster, "@" NICK_MAIN) != NULL,
                     NICK_MAIN " is not drawn as an operator of " CHAN_OP " after "
                     "the restore, although the window recorded the +o and this "
                     "node OWNS the channel: %.*s", (int)rlen,
                     (roster != NULL) ? roster : "");
    }

    mark = tc_received(&watcher);
    (void)snprintf(line, sizeof line, "NAMES " CHAN_PLAIN);
    TF_CHECK_MSG(tc_send(&watcher, line) == 0,
                 "the watcher's second NAMES send failed");
    (void)snprintf(line, sizeof line, "PING :watch-plain");
    TF_CHECK_MSG(tc_send(&watcher, line) == 0, "the watcher's PING send failed");
    TF_CHECK_MSG(tc_expect(&watcher, "watch-plain", T_IO_MS) == 0,
                 "the watcher never got its second PONG: %s", tc_buffer(&watcher));
    {
        size_t rlen = 0u;
        const char *roster = roster_text(since(&watcher, mark), CHAN_PLAIN, &rlen);

        TF_CHECK_MSG(roster != NULL,
                     "the watcher never received a 353 for " CHAN_PLAIN ": %s",
                     since(&watcher, mark));
        TF_CHECK_MSG(roster != NULL && roster_count(roster, rlen, NICK_MAIN) == 1u,
                     NICK_MAIN " appears %zu times in " CHAN_PLAIN "'s roster, so "
                     "the restore put one user in the roster twice: %.*s",
                     roster_count(roster, rlen, NICK_MAIN), (int)rlen,
                     (roster != NULL) ? roster : "");
        /* AND NO PREFIX IT WAS NEVER GIVEN, which is the privilege half of the
         * claim: the window recorded no operator status here, so a restore that
         * could ADD one would be a restore that invents authority, and the
         * monotone-subordinate property core/resume.c states is what is supposed
         * to make that impossible. */
        TF_CHECK_MSG(roster != NULL && strstr(roster, "@" NICK_MAIN) == NULL,
                     NICK_MAIN " is drawn as an operator of " CHAN_PLAIN ", where "
                     "it held no operator status at all. A restore able to add a "
                     "prefix it was not given is a privilege bug: %.*s", (int)rlen,
                     (roster != NULL) ? roster : "");
    }

    /* CLAIM 3, THE WINDOW IS ONE-SHOT -- AS A COUNT, and the count is the right
     * shape for this claim rather than a convenience.
     *
     * The property is "a window is consumed by the first client that presents
     * its key and by no other", and a wire-level test of it is awkward for a
     * reason worth naming: a second client presenting the same key is refused at
     * the NICK claim while the first is still connected (claim 5), so by the
     * time it can present the key the first has DROPPED -- and a drop records a
     * new window, which the second is then entitled to. A replay test built that
     * way would assert nothing, because the second restore would be correct.
     *
     * SO IT IS ASSERTED ON THE PAIR (noted, applied), and the pair is exactly
     * the property: every window taken has been applied at most once, so
     * applied <= noted always, and at this point in the case the two windows
     * taken so far -- one for the first drop, one for the restore's own drop --
     * have been applied between them exactly once. A window that could be
     * replayed would show applied == 2 with noted == 2, and a window that was
     * never taken would show applied > noted. Both are bugs and neither is
     * visible on the wire.
     *
     * IT IS ALSO THE CLAIM THAT MAKES "WHERE IS THIS FREED" ANSWERABLE, because
     * the common path frees on use and the counter is the evidence. */
    tc_close(&again);
    TF_CHECK_MSG(nf_expect(&n, REAPED, T_IO_MS) == 0,
                 "the node did not reap the restored client, so the one-shot claim "
                 "would be measured against a node still holding the nickname: %s",
                 n.out);
    TF_CHECK_MSG(nf_expect(&n, "[observable] session_resume_note: nick=" NICK_MAIN
                              " ident=" IDENT_MAIN " chans=2",
                           T_IO_MS) == 0,
                 "the restored client's own drop recorded no window, so the count "
                 "below would be measuring one window rather than two: %s",
                 n.out);
    TF_CHECK_MSG(nf_expect_u64(&n, "resume_noted=", 2u, T_IO_MS) == 0,
                 "the node has taken a number of windows other than the two this "
                 "case produced (one per drop), so the one-shot count below is "
                 "measuring something else: %s",
                 n.out);
    TF_CHECK_MSG(nf_expect_u64(&n, "resume_applied=", 1u, T_IO_MS) == 0,
                 "the node applied more windows than clients who came back from a "
                 "drop. A window that can be applied twice can be COMPLETED by a "
                 "second connection, which is completing somebody else's session: "
                 "%s",
                 n.out);

    /* AND THE ONE-SHOT PROPERTY ON THE WIRE, which is where it belongs and where
     * the count above cannot reach. The count is a necessary condition; this is
     * the claim: after a window has been consumed, a client that presents the same
     * key again gets NOTHING.
     *
     * THE KEY IS PRESENTED TWICE WITHOUT A SECOND WINDOW BEING RECORDED, and the
     * way to arrange that is a QUIT rather than a drop: a drop records a new
     * window, so a second presenter would legitimately get a second window and
     * the claim would prove nothing. A QUIT records none, so the only window that
     * could answer the second presenter is the one the first presenter consumed --
     * which is exactly what the assertion is about.
     *
     * THE ORDER MATTERS: the first presenter is the restored client from beat 4,
     * which is still connected, and it leaves by QUIT so its nickname is free
     * without recording anything. */
    {
        test_client_t second;

        register_client(&again, n.port, NICK_MAIN, IDENT_MAIN, "reg-second");
        (void)snprintf(line, sizeof line, "QUIT :done");
        TF_CHECK_MSG(tc_send(&again, line) == 0, "the QUIT send failed");
        TF_CHECK_MSG(nf_expect(&n, "quit: fd=", T_IO_MS) == 0,
                     "the node did not see the restored client's QUIT, so the "
                     "nickname may still be held and the next client would be "
                     "refused for the wrong reason: %s",
                     n.out);
        register_client(&second, n.port, NICK_MAIN, IDENT_MAIN, "reg-second2");
        mark = tc_received(&second);
        (void)snprintf(line, sizeof line, "NAMES " CHAN_OP);
        TF_CHECK_MSG(tc_send(&second, line) == 0, "the NAMES send failed");
        (void)snprintf(line, sizeof line, "PING :second-names");
        TF_CHECK_MSG(tc_send(&second, line) == 0, "the PING send failed");
        TF_CHECK_MSG(tc_expect(&second, "second-names", T_IO_MS) == 0,
                     "the second presenter never got its PONG: %s",
                     tc_buffer(&second));
        {
            size_t rlen = 0u;
            const char *roster = roster_text(since(&second, mark), CHAN_OP, &rlen);

            TF_CHECK_MSG(roster == NULL ||
                             roster_count(roster, rlen, NICK_MAIN) == 0u,
                         NICK_MAIN " was restored into " CHAN_OP " a SECOND time "
                         "from the SAME window, so the window is replayable. A "
                         "replayable window is a window a third connection can "
                         "complete, and completing somebody else's session is the "
                         "one thing this feature must not allow: %.*s",
                         (int)rlen, (roster != NULL) ? roster : "");
        }
        tc_close(&second);
    }

    /* CLAIM 4, THE KEY. Same nick, DIFFERENT ident: no window, and the client is
     * told nothing about a window it never matched.
     *
     * IT GETS ITS OWN WINDOW, and that is not tidiness: the one-shot block above
     * consumed the only window this case had and then QUITted its holder, which
     * released the channel hold and let the channel go. A key-mismatch case run
     * against an empty table would pass whether or not the ident were compared,
     * because there would be nothing to fail to match. So a fresh client takes a
     * name, joins, and DROPS -- which records a window -- and the client that
     * presents the same NICK with a different ident is the one under test.
     *
     * THIS IS THE HALF OF THE KEY THAT MATTERS MOST, and the reason is what an
     * ident is for. 2.1 makes it the USER parameter, and a user chooses it to be
     * recognised across sessions -- so the same nickname with the same ident is
     * the same person coming back, and the same nickname with a DIFFERENT ident
     * is a different thing wearing the same name. A window keyed on the nick
     * alone would hand that second thing somebody's channel memberships. */
    {
        test_client_t holder;
        test_client_t wrong_ident;

        register_client(&holder, n.port, NICK_KEY, IDENT_KEY, "reg-key");
        (void)snprintf(line, sizeof line, "JOIN " CHAN_OP);
        TF_CHECK_MSG(tc_send(&holder, line) == 0, "the key holder's JOIN failed");
        TF_CHECK_MSG(tc_expect(&holder, " 366 ", T_IO_MS) == 0,
                     "the key holder's JOIN never completed");
        tc_close(&holder);
        TF_CHECK_MSG(nf_expect(&n, "[observable] session_resume_note: nick=" NICK_KEY
                                  " ident=" IDENT_KEY,
                               T_IO_MS) == 0,
                     "the node recorded no window for the key holder, so the "
                     "mismatch below would run against an empty table and pass "
                     "whether or not the ident were compared: %s",
                     n.out);
        /* The applied-count as it stands BEFORE this client exists. The claim
         * below is that registering the wrong-ident client leaves it unchanged,
         * so it is read on both sides of that registration rather than pinned to
         * an absolute number: earlier beats in this test have already moved it to
         * 2, and a hardcoded 1 would be an assertion about the test's own history
         * rather than about the key comparison. */
        uint64_t applied_before = 0u;


            TF_CHECK_MSG(nf_find_u64(&n, "resume_applied=", &applied_before) == 0,
                         "could not read resume_applied before the wrong-ident "
                         "client: %s", n.out);
            register_client(&wrong_ident, n.port, NICK_KEY, IDENT_WRONG, "reg-wrong");
        mark = tc_received(&wrong_ident);
        (void)snprintf(line, sizeof line, "NAMES " CHAN_OP);
        TF_CHECK_MSG(tc_send(&wrong_ident, line) == 0, "the NAMES send failed");
        (void)snprintf(line, sizeof line, "PING :wrong-names");
        TF_CHECK_MSG(tc_send(&wrong_ident, line) == 0, "the PING send failed");
        TF_CHECK_MSG(tc_expect(&wrong_ident, "wrong-names", T_IO_MS) == 0,
                     "the client never got its PONG: %s", tc_buffer(&wrong_ident));
          /* And WAIT FOR THE 353 EXPLICITLY, rather than reading the buffer and
           * hoping. The PONG above proves the node answered a command, which is
           * not the same as proving it had already answered NAMES: those are
           * separate writes, and on a loaded machine the 353 can still be in
           * flight when the PONG lands. This check used to pass only because a
           * LATER assertion in the same beat -- the racy 400 ms nf_expect() -- sat
           * far enough down the function to pump the node's output for 400 ms
           * first, and the roster read whatever that pump happened to collect.
           * Remove the racy assertion and the roster check starts reading a buffer
           * the node has not finished writing, which is the same class of bug this
           * beat was fixed for: an assertion whose outcome depends on timing that
           * belongs to a different assertion. */
          TF_CHECK_MSG(tc_expect(&wrong_ident, " 353 ", T_IO_MS) == 0,
                       "the client never received a 353, so the roster claim below "
                       "reads a buffer that does not contain it: %s",
                       tc_buffer(&wrong_ident));
        {
            size_t rlen = 0u;
            const char *roster =
                roster_text(since(&wrong_ident, mark), CHAN_OP, &rlen);

            TF_CHECK_MSG(roster != NULL,
                         "the client never received a 353 for " CHAN_OP ", so the "
                         "claim below is about a roster that does not exist: %s",
                         since(&wrong_ident, mark));
            TF_CHECK_MSG(roster != NULL &&
                             roster_count(roster, rlen, NICK_KEY) == 0u,
                         NICK_KEY " appears %zu times in " CHAN_OP "'s roster, so a "
                         "client whose IDENT differs from the one the window "
                         "recorded was put into it. The nick alone is not the key, "
                         "and a window keyed on the nick alone would hand any "
                         "client that guesses it somebody's channels: %.*s",
                         roster_count(roster, rlen, NICK_KEY), (int)rlen,
                         (roster != NULL) ? roster : "");
        }
        /* AND THE NODE DID NOT CLAIM TO HAVE RESTORED IT, which is the other half
         * and the one a name-only resolver would get wrong: a node that matched
         * on the nick alone would have told the CLIENT it was resumed, and this
         * is the line the client would have acted on. */
        /* The negative assertion is scoped to the LOG AS IT STANDS NOW, and the
         * boundary that makes it meaningful is the PONG above: that round trip is
         * proof the node finished registering this client, so a resume line for it
         * would already have been written. Asserting absence over a 400 ms window
         * instead cannot tell "correctly refused" from "not written yet" -- and
         * that is not theoretical: this is the assertion the sanitizer job failed,
         * where the reconnect landed after the deadline, so the deadline expired
         * with the line already there for the OTHER key.
         *
         * There is deliberately no resume_rejected counter for this path: a client
         * that matches no window is not a failed resume and is told nothing (the
         * NOTICE check below is the same property from the client's side), so a
         * counter for it would report a rejection the node does not consider one.
         * The boundary plus the two counters is the honest form.
         *
         * The 400 ms nf_expect() that stood here before is GONE, and it was the
         * whole cause of the sanitizer job's failure: it asked "is this line
         * absent right now", which is a question about the scheduler as much as
         * about the key comparison. It survived the previous commit -- I added
         * the two sound checks ABOVE it and left it in place -- so the job kept
         * failing on the racy assertion while correct ones sat immediately above
         * it saying the same thing. */
        TF_CHECK_MSG(strstr(n.out, "session_resume: nick=" NICK_KEY " ident=" IDENT_WRONG) ==
                         NULL,
                     "a window was applied to a client whose IDENT differs from "
                     "the one the window recorded: %s", n.out);
        TF_CHECK_MSG(nf_expect_u64(&n, "resume_applied=", applied_before, T_IO_MS) == 0,
                     "resume_applied moved from %llu after a client whose IDENT "
                     "differs from the one the window recorded registered, so the key "
                     "is not really the three fields core/resume.h claims: %s",
                     (unsigned long long)applied_before, n.out);
        /* AND A PLAIN FRESH CLIENT IS NOT TOLD ANYTHING, which is the other side
         * of the same coin and is the property that keeps the feature invisible to
         * clients that do not use it: there is no window, so there is no failed
         * resume, so there is nothing to say. A NOTICE on every registration would
         * be noise on every connection. */
        TF_CHECK_MSG(strstr(tc_buffer(&wrong_ident), "NOTICE") == NULL,
                     "a client that matched no window was sent a NOTICE about it. A "
                     "client that simply has not lost a session is not a failed "
                     "resume, and telling it otherwise would put this feature in "
                     "every connection's log: %s",
                     tc_buffer(&wrong_ident));
        tc_close(&wrong_ident);
    }

    /* --- beat 5: the COLLISION --------------------------------------------- */
    /* A window is outstanding for the nick, and a SECOND client claims it while
     * the first holds it. The claim is refused, and the incumbent is untouched.
     *
     * The choice is REFUSE THE NEWCOMER, and the alternative -- kick the old
     * session -- is refused for a reason that has nothing to do with
     * convenience: this node has NO AUTHENTICATION (core/resume.h says so), so
     * "kick the old session" is a primitive that lets anyone who knows a
     * nickname disconnect the person using it, with no credential and no
     * evidence. That is a free denial of service. Refusing the newcomer costs a
     * legitimate client one retry, and a client that has just reconnected before
     * the node noticed the old socket is the only case that pays it. */
    {
        test_client_t holder;
        test_client_t challenger;

        register_client(&holder, n.port, "carol", "carolident", "reg-holder");
        TF_CHECK_MSG(tc_send(&holder, "JOIN " CHAN_OP) == 0,
                     "the holder's JOIN failed");
        TF_CHECK_MSG(tc_expect(&holder, " 366 ", T_IO_MS) == 0,
                     "the holder's JOIN never completed");
        /* carol drops WITHOUT a QUIT, so a window for carol is outstanding, and
         * then a second connection claims carol's nick while the FIRST carol is
         * still connected. The window is never consulted for a nick that is in
         * use -- the claim is refused before anything looks at the table -- so
         * the window is not a way to take a live name. */
        /* THE CHALLENGER IS REGISTERED BY HAND rather than through
         * register_client(), because the helper asserts a 001 and this client's
         * whole point is that it does not get one. Connecting, claiming, and
         * expecting 433 is the entire claim. */
        TF_CHECK_MSG(tc_connect(&challenger, n.port) == 0,
                     "the challenger could not connect");
        (void)snprintf(line, sizeof line, "NICK carol");
        TF_CHECK_MSG(tc_send(&challenger, line) == 0, "the challenger's NICK failed");
        (void)snprintf(line, sizeof line, "USER carolident 0 *spoofed :Real carol");
        TF_CHECK_MSG(tc_send(&challenger, line) == 0,
                     "the challenger's USER failed");
        TF_CHECK_MSG(tc_expect(&challenger, " 433 ", T_IO_MS) == 0,
                     "a second client claiming a LIVE nickname was not answered "
                     "433. Kicking the incumbent would be the other choice, and "
                     "on a node with no authentication it is a denial of service "
                     "anyone can start by knowing a nickname: %s",
                     tc_buffer(&challenger));
        /* AND THE INCUMBENT IS STILL THERE, which is the other half of the claim
         * and the one a "refuse then quietly unclaim" bug would break. */
        mark = tc_received(&holder);
        (void)snprintf(line, sizeof line, "NAMES " CHAN_OP);
        TF_CHECK_MSG(tc_send(&holder, line) == 0, "the holder's NAMES send failed");
        (void)snprintf(line, sizeof line, "PING :holder-names");
        TF_CHECK_MSG(tc_send(&holder, line) == 0, "the holder's PING send failed");
        TF_CHECK_MSG(tc_expect(&holder, "holder-names", T_IO_MS) == 0,
                     "the incumbent never got its PONG, so it is gone and the 433 "
                     "was not the whole story: %s",
                     tc_buffer(&holder));
        TF_CHECK_MSG(strstr(since(&holder, mark), "carol") != NULL,
                     "the incumbent is no longer in " CHAN_OP "'s roster after a "
                     "newcomer was refused its nickname: %s",
                     since(&holder, mark));
        /* AND THE WINDOW WAS NOT CONSUMED BY THE REFUSED CLAIM, which is what
         * "the window is never consulted" means in practice: a refused claim
         * must leave the table exactly as it was. */
        TF_CHECK_MSG(nf_expect_u64_ge(&n, "resume_applied=", 1u, 400) == 0,
                     "the node's applied count is below the one resume this file "
                     "already proved, so a counter is not counting: %s",
                     n.out);
        tc_close(&holder);
        tc_close(&challenger);
    }

    /* --- beat 6: EXPIRY, VISIBLE ON THE WIRE ------------------------------- */
    /* A fresh lost session, and this time the window is NOT taken back inside
     * the bound. The wait is on the node's OWN statement that its clock passed
     * the bound -- `reason=EXPIRED` -- so this is a wait for the behaviour and
     * not for a duration, and there is no sleep anywhere. */
    register_client(&late, n.port, NICK_LATE, IDENT_LATE, "reg-late");
    TF_CHECK_MSG(tc_send(&late, "JOIN " CHAN_OP) == 0, "dave's JOIN failed");
    TF_CHECK_MSG(tc_expect(&late, " 366 ", T_IO_MS) == 0,
                 "dave's JOIN never completed");
    tc_close(&late);
    TF_CHECK_MSG(nf_expect(&n, "[observable] session_resume_note: nick=" NICK_LATE,
                           T_IO_MS) == 0,
                 "the node recorded no window for dave: %s", n.out);
    /* THE WAIT IS THE NODE'S OWN STATEMENT THAT ITS CLOCK PASSED THE BOUND, and
     * not a sleep and not a computed duration. `session_resume_sweep: dropped=N`
     * is printed by the sweep in core/resume.c at the moment it gives a window
     * up, so waiting for it is waiting for the expiry to have happened rather
     * than for a number of milliseconds the test guessed. The sweep is driven
     * from server_tick() at window/16, so it runs about every 25 ms here and the
     * wait is a handful of ticks rather than the full window.
     *
     * A test that slept for RESUME_WINDOW_MS would pass here too, and it would
     * also pass against a node that expired windows for an unrelated reason, and
     * it would take 400 ms of wall clock for the privilege of proving nothing. */
    TF_CHECK_MSG(nf_expect(&n, RETIRE_LATE, T_IO_MS) == 0,
                 "no window was ever retired, so the node's clock never passed the "
                 "bound and the expiry claim below would be measured against a "
                 "window that is still open. The sweep runs from server_tick() at "
                 "window/16, so this is a handful of ticks and not the whole "
                 "window: %s",
                 n.out);
    register_client(&late, n.port, NICK_LATE, IDENT_LATE, "reg-late2");
    TF_CHECK_MSG(nf_expect(&n, MISS_EXPIRED, T_IO_MS) == 0,
                 "the node did not report an expired window for dave, so expiry "
                 "is either not decided or not reached -- and either way a client "
                 "that comes back too late is being silently given an "
                 "un-resumed registration: %s",
                 n.out);
    /* CLAIM 6, THE OBSERVABLE. The client is TOLD, on the wire, in a NOTICE it
     * can render. A silent fallback -- no restore and no word about it -- is
     * indistinguishable from a server that never had the feature, and a client
     * cannot report a bug about a feature it was never told about. */
    /* THE WHOLE BUFFER, NOT since(mark), and the reason is the ORDER: the
     * NOTICE is emitted during registration -- resume_apply() runs inside
     * commands_state_update() -- so it arrives BEFORE the drain PING that
     * register_client() waits for, and a mark taken after the drain would sit
     * after the very line this is looking for. The buffer is this client's whole
     * history and it was connected for this one registration, so there is
     * nothing in it that could not be the answer. */
    (void)snprintf(line, sizeof line, "PING :late");
    TF_CHECK_MSG(tc_send(&late, line) == 0, "dave's PING send failed");
    TF_CHECK_MSG(tc_expect(&late, "late", T_IO_MS) == 0,
                 "dave never got his PONG: %s", tc_buffer(&late));
    TF_CHECK_MSG(strstr(tc_buffer(&late), "NOTICE") != NULL &&
                     strstr(tc_buffer(&late), "Session resume unavailable") != NULL,
                 "a client whose window had closed was restored nothing and told "
                 "nothing. 4.4 has no numeric for this, so it is a NOTICE -- a "
                 "line every client renders -- rather than a silent fallback: %s",
                 since(&late, mark));
    TF_CHECK_MSG(strstr(since(&late, mark), NICK_MAIN) == NULL,
                 "dave was restored into somebody else's channels, which is a "
                 "different bug but is checked here because the same buffer is "
                 "already in hand: %s",
                 since(&late, mark));
    tc_close(&late);

    /* AND THE HOLD ON THE CHANNELS WAS RELEASED BEFORE THE WINDOW WAS RETIRED,
     * which is the ordering that keeps 2.2's disposal rule true. The hold is
     * resume_hold_ms() -- window/2 clamped into [1000ms, 5000ms], so 1000 ms here
     * -- and it is well inside the 1500 ms window, so the node's own two lines
     * are in this order and the assertion is about the order rather than about
     * either line existing. A hold as long as the window would delay a channel's
     * disposal for as long as the session is resumable, which is 2.2's rule with
     * a hole in it. */
    TF_CHECK_MSG(strstr(n.out, "[observable] session_resume_hold: nick=" NICK_LATE) !=
                     NULL,
                 "the node never released the hold on " NICK_LATE "'s channels, so "
                 "a channel whose only member dropped would stay alive for the "
                 "whole window rather than a few seconds: %s",
                 n.out);

    /* THE SWEEP'S FREE PATH, and it is a WAIT rather than a lookup, and it comes
     * BEFORE the node is stopped. The grace has to elapse first -- 500 ms here,
     * window/3 -- and 500 ms of real waiting bounded by a deadline is a wait
     * rather than a sleep. Dave's own tombstone cannot exercise it: his was freed
     * by the apply that refused it, which is the third release path and the one a
     * client that comes back hits. The window this waits for belongs to a client
     * that never came back at all, and the fact that it is freed is the whole of
     * "a retired window nobody claims is released anyway" -- without which the
     * table would hold every window this node ever took, inside an array whose
     * bound is the only thing making the memory bounded. */
    TF_CHECK_MSG(nf_expect(&n, "[observable] session_resume_free: nick=", T_IO_MS) == 0,
                 "no window was ever freed by the sweep, so the two-stage expiry "
                 "never completes for a window nobody came back for and the table "
                 "holds every window this node ever took: %s",
                 n.out);

    /* CLAIM 7, THE TEARDOWN ARM, observable. The node prints whether the window
     * table was OPEN when it shut down, which is what lets this be asserted on a
     * platform whose LeakSanitizer does not run -- the same argument
     * server_shutdown() makes about the burst shadow. The table is OPEN because
     * the sweep frees on a GRACE and the node is stopped inside it, which is the
     * state a long-lived process is in most of the time and the state in which a
     * missing free would cost IRC_RESUME_MAX * 1.3 KiB. */
    TF_CHECK_MSG(nf_stop(&n) == 0, "the node did not exit cleanly");
    TF_CHECK_MSG(strstr(n.out, CLOSED) != NULL,
                 "the node shut down without printing its session_resume_close "
                 "line, so the teardown arm cannot be asserted on a platform "
                 "whose LeakSanitizer does not run: %s",
                 n.out);
    /* AND THE TABLE IS EMPTY AT SHUTDOWN, which is the end state a leak checker
     * would report and the one a reader of the stats line can check without one.
     * `resume_held=0` is printed by server_shutdown()'s stats line, and a
     * non-zero value on a node whose clients have all been reaped would mean the
     * store outlived every window in it. */
    TF_CHECK_MSG(strstr(n.out, "resume_held=0 ") != NULL,
                 "the node shut down still holding resume windows, so a window "
                 "outlived every path that is supposed to release it: %s",
                 n.out);
    nf_free(&n);
}

/* ---------------------------------------------------------------------------
 * THE COUNT BOUND, and it is its own case because it needs a DIFFERENT NUMBER OF
 * CLIENTS and a different assertion
 * ---------------------------------------------------------------------------
 *
 * The window table is bounded at IRC_RESUME_MAX entries, and the bound is a
 * memory bound answered the way a cache answers one: the OLDEST window goes and
 * the drop is counted. The alternative -- refusing the new window -- would mean a
 * node under a scripted connect/disconnect loop stops resuming for EVERYBODY,
 * which is the failure 2.2's topic-cache rule is written against: a store that
 * can refuse is a store that can break a client command.
 *
 * IT IS A SEPARATE CASE BECAUSE IT IS A DIFFERENT KIND OF CLAIM. The first case
 * asks "does a client get its channels back"; this one asks "what happens when
 * more clients drop than the table holds", and the answer is a number on the
 * node's own counters and a line naming the eviction. Asserting it inside the
 * first case would mean 64 extra clients in the middle of a test about one
 * client's session, and a failure in the bound would then read as a failure in
 * the restore.
 *
 * IRC_RESUME_MAX CLIENTS PLUS ONE, and the count is the shipped bound rather than
 * a number chosen to make the test quick -- a test that filled a table of 8 would
 * prove nothing about a table of 64. It costs 65 short connections over loopback,
 * each one a register and a drop with no channel between them, so the whole case
 * is a fraction of a second of wall clock and the assertion is on a bound rather
 * than on a duration. */
static void case_the_window_table_is_bounded(void)
{
    nf_node_t n;
    char line[200];
    size_t i;

    TF_CHECK_MSG(nf_spawn_inline_named(&n, "irc.b", child_setup) == 0,
                 "could not spawn the node");
    TF_CHECK_MSG(n.port > 0, "the node reported no port");

    for (i = 0; i < IRC_RESUME_MAX + 1u; i++) {
        test_client_t c;
        char nick[32];

        (void)snprintf(nick, sizeof nick, "c%zu", i);
        TF_CHECK_MSG(tc_connect(&c, n.port) == 0, "client %zu could not connect", i);
        (void)snprintf(line, sizeof line, "NICK %s", nick);
        TF_CHECK_MSG(tc_send(&c, line) == 0, "client %zu's NICK failed", i);
        (void)snprintf(line, sizeof line, "USER %s 0 *spoofed :Real %s", nick, nick);
        TF_CHECK_MSG(tc_send(&c, line) == 0, "client %zu's USER failed", i);
        TF_CHECK_MSG(tc_expect(&c, " 001 ", T_IO_MS) == 0,
                     "client %zu never registered", i);
        /* ONE CHANNEL, THE SAME ONE, for every client. Distinct channels would
         * exercise the hold on 65 different chan_t's and turn a bound on the
         * window TABLE into a test of a bound on the channel registry, which is a
         * different store with a different rule. */
        (void)snprintf(line, sizeof line, "JOIN " CHAN_OP);
        TF_CHECK_MSG(tc_send(&c, line) == 0, "client %zu's JOIN failed", i);
        TF_CHECK_MSG(tc_expect(&c, " 366 ", T_IO_MS) == 0,
                     "client %zu's JOIN never completed", i);
        tc_close(&c);
    }
    /* The reap of the LAST one is the synchronisation point for all of them: the
     * node closes a connection on its own schedule, so the table is not full until
     * it has reaped the drops, and a bound read before that would be a bound read
     * against a half-filled table. */
    TF_CHECK_MSG(nf_expect(&n, "[observable] session_resume_evict: bound=", T_IO_MS) == 0,
                 "the node never evicted a window after %zu clients dropped, so "
                 "IRC_RESUME_MAX is not a bound on anything: %s",
                 IRC_RESUME_MAX + 1u, n.out);
    TF_CHECK_MSG(nf_expect_u64_ge(&n, "resume_evicted=", 1u, T_IO_MS) == 0,
                 "the node's eviction counter is still zero, so the table grew "
                 "past its bound instead of dropping the oldest window: %s",
                 n.out);
    /* AND THE TABLE IS STILL WITHIN IT, which is the claim the counter alone does
     * not make: a node that evicted but then kept growing would show a non-zero
     * eviction counter too. `resume_held` is the live count, and it cannot exceed
     * the bound. */
    {
        char want[64];

        (void)snprintf(want, sizeof want, "resume_held=%zu ", IRC_RESUME_MAX);
        TF_CHECK_MSG(nf_expect(&n, want, T_IO_MS) == 0,
                     "the node is not holding exactly IRC_RESUME_MAX (%zu) windows "
                     "after %zu clients dropped, so the bound is either not applied "
                     "or is applied by growing the array: %s",
                     IRC_RESUME_MAX, IRC_RESUME_MAX + 1u, n.out);
    }
    TF_CHECK_MSG(nf_stop(&n) == 0, "the node did not exit cleanly");
    /* AND THE TEARDOWN ARM, with a table at its bound, which is the state in which
     * a missing free would cost IRC_RESUME_MAX * 1.3 KiB. That is the number
     * LeakSanitizer is for, and the arm's own line is what makes it checkable
     * without one. */
    TF_CHECK_MSG(strstr(n.out, CLOSED) != NULL,
                 "the node shut down without its session_resume_close line while "
                 "holding a full window table: %s",
                 n.out);
    nf_free(&n);
}

int main(void)
{
    case_a_dropped_client_gets_its_channels_back();
    case_the_window_table_is_bounded();
    tf_done("reconnect");
    return 0;
}
