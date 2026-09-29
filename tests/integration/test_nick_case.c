/* test_nick_case.c -- nicknames are case-INsensitive, and the case a user chose
 * is the case everybody sees. Issue #100.
 *
 * RFC 2812 2.3.1 and docs/SERVER_DESIGN.md 2.1 both say a nickname is
 * case-insensitive, and 2.1 promises that uniqueness is enforced per server with
 * no policy and no lock. Before the registry folded, neither half was true:
 * `PRIVMSG BOB :hi` answered 401 to a user connected as `bob`, and `bob` and
 * `BOB` occupied two different registry slots, so BOTH could be claimed at once.
 *
 * ---------------------------------------------------------------------------
 * WHAT IS ASSERTED, AND WHY THESE FOUR NUMERICS
 * ---------------------------------------------------------------------------
 * The whole point of the fix is a rule about COMPARISON, so a test that only
 * checked one command could be satisfied by a node that got lucky on one path.
 * The rule is checked where a client can actually observe it:
 *
 *   353  the roster, rendered from conn_t::nick -- a nick's display case
 *   352  WHO, likewise
 *   311  WHOIS, likewise
 *   prefix  every delivered line, likewise
 *
 * and where it can be observed being VIOLATED:
 *
 *   433  claiming a name that differs only in case from a held one
 *
 * Between those, the four facts the issue lists are each asserted separately,
 * because they fail independently: a registry can resolve correctly and still
 * let a duplicate be claimed (section 4), and it can refuse the duplicate while
 * rendering the wrong case to everybody (section 1).
 *
 * ---------------------------------------------------------------------------
 * "THE DISPLAY CASE SURVIVES" IS NOT THE SAME ASSERTION AS "IT FOLDS"
 * ---------------------------------------------------------------------------
 * Folding the stored nickname would make every lookup correct and every
 * assertion in sections 1-3 pass, while breaking the one thing IRC clients
 * actually display. A user who registers as `Bob` must be `Bob` in 353, in a
 * message prefix, in 352 and in 311 -- and each of those is asserted with its
 * FULL exact line, so a node that rendered `bob` or `BOB` fails on the bytes
 * rather than on a needle that happens to tolerate either.
 *
 * Every assertion is on wire bytes, per CONTRIBUTING.md. Nothing here reads a
 * conn_t, a server_t or a struct field, and there is no sleep() anywhere: every
 * wait is a PING/PONG deadline round-trip or tc_expect(), and every "nothing
 * arrived" is scoped to a window closed by a PONG the node could not answer
 * before it had finished with the command under test.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

#define T_READY_MS 15000
#define T_IO_MS 15000

/* The shipped binary's node name. Every numeric and prefix carries it. */
#define BIN_NAME "irc.test"

/* The host every client here connects FROM. The USER line every client sends
 * names a DIFFERENT host in RFC 2812 3.1's <unused> slot, and no assertion below
 * is allowed to match it -- so a node that had regressed to echoing the client's
 * claim instead of what accept() observed fails the prefix checks. */
#define OBSERVED_HOST "127.0.0.1"
#define CLAIMED_HOST "spoofed.example"

static size_t   g_opened;
static unsigned g_drain_seq;

typedef struct {
    test_client_t c;
    char          nick[72];
} client_t;

/* ---------------------------------------------------------------------------
 * THE WINDOW PRIMITIVE
 * ---------------------------------------------------------------------------
 * A window is [from, end): `from` is a PING's PONG sent BEFORE the command under
 * test, `end` a second PING's PONG sent after it. Because a connection's answers
 * are written in order, the closing PONG proves every earlier answer is already
 * in the buffer. So the window is closed by a fact about the node rather than by
 * a wait, which is how "nothing arrived" is asserted without a fixed sleep --
 * CONTRIBUTING.md's rule, and the reason a negative here is a statement rather
 * than a guess.
 *
 * The token is unique per call. A repeated one would match its own earlier PONG
 * and the wait would return instantly, so the window would close before the
 * command under test had been answered at all.
 */
static size_t drain(client_t *cl)
{
    char line[64];
    char needle[96];
    const char *at;

    g_drain_seq++;
    (void)snprintf(line, sizeof line, "PING :n%u", g_drain_seq);
    (void)snprintf(needle, sizeof needle, "PONG %s n%u\r\n", BIN_NAME,
                   g_drain_seq);
    TF_CHECK_MSG(tc_send(&cl->c, line) == 0, "drain PING send failed");
    TF_CHECK_MSG(tc_expect(&cl->c, needle, T_IO_MS) == 0, "no PONG for %s", line);
    at = strstr(tc_buffer(&cl->c), needle);
    TF_CHECK_MSG(at != NULL, "the drain PONG vanished from the buffer");
    return (at != NULL) ? (size_t)(at - tc_buffer(&cl->c)) : 0u;
}

static size_t open_window(client_t *cl)
{
    return drain(cl);
}

/* `want` must appear in the window, terminated, at a line boundary. The CRLF is
 * part of the needle so a match proves the line is TERMINATED on the wire rather
 * than being a prefix of a longer one, and the boundary is checked so a match
 * that is the SUFFIX of another line cannot pass. */
static void expect_in_window(client_t *cl, size_t from, size_t end,
                             const char *what, const char *want)
{
    const char *base = tc_buffer(&cl->c);
    const char *at;

    TF_CHECK_MSG(end > from, "%s: the window was never closed (from=%zu end=%zu)",
                 what, from, end);
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

/* `needle` must NOT appear anywhere in the window, and the window must have been
 * closed -- an unclosed window would make this a statement about a buffer the
 * node may not have finished writing to. */
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
                 "%s: \"%s\" appeared %zu time(s) in the window and must not "
                 "have appeared at all",
                 what, needle, count);
}

/* Non-overlapping occurrences of `needle` in the window. Scoped for the reason
 * the two helpers above are: a count over the whole buffer would include every
 * earlier exchange, so "no new 433" would be a statement about the session
 * rather than about the command just sent. */
static size_t count_in_window(const client_t *cl, size_t from, size_t end,
                              const char *needle)
{
    const char *base = tc_buffer(&cl->c);
    size_t n = 0;

    for (const char *p = base + from; p < base + end;) {
        const char *hit = strstr(p, needle);

        if (hit == NULL || hit >= base + end) {
            break;
        }
        n++;
        p = hit + strlen(needle);
    }
    return n;
}

/* The workhorse: `cl` sends `line`, and the answer is checked in a window opened
 * before and closed after it. */
static void send_expect(client_t *cl, const char *line, const char *want)
{
    size_t from = open_window(cl);
    size_t end;

    TF_CHECK_MSG(tc_send(&cl->c, line) == 0, "tc_send(%s) failed", line);
    end = drain(cl);
    expect_in_window(cl, from, end, line, want);
}

/* ---------------------------------------------------------------------------
 * CLIENTS
 * ---------------------------------------------------------------------------
 * One registration path, so no scenario below can accidentally assert a verb
 * against an unregistered connection and get a 451 for a reason that has nothing
 * to do with case.
 *
 * `nick` is passed through VERBATIM, which is the whole point of this file:
 * "Bob" here is a nickname with a capital B, and the node must hold exactly that.
 */
static void client_open(client_t *cl, nf_node_t *node, const char *nick)
{
    char line[256];

    tc_init(&cl->c);
    (void)snprintf(cl->nick, sizeof cl->nick, "%s", nick);
    g_opened++;
    TF_CHECK_MSG(tc_connect(&cl->c, node->port) == 0, "tc_connect(%s) failed",
                 nick);
    (void)snprintf(line, sizeof line, "NICK %s", nick);
    TF_CHECK_MSG(tc_send(&cl->c, line) == 0, "NICK send failed");
    /* RFC 2812 3.1: USER <user> <mode> <unused> :<realname>. The third parameter
     * is the one older clients fill with a hostname, which is why it is the one
     * worth lying in: a node that stored it would put a value the client chose
     * into every prefix it emits. */
    (void)snprintf(line, sizeof line, "USER %s 0 *%s :Real %s", nick,
                   CLAIMED_HOST, nick);
    TF_CHECK_MSG(tc_send(&cl->c, line) == 0, "USER send failed");
    TF_CHECK_MSG(tc_expect(&cl->c, " 001 ", T_IO_MS) == 0, "%s did not register",
                 nick);
    TF_CHECK_MSG(tc_send(&cl->c, "PING :reg-drain") == 0, "PING send failed");
    TF_CHECK_MSG(tc_expect(&cl->c, "PONG ", T_IO_MS) == 0,
                 "%s: no PONG after registration", nick);
}

/* Connect, and nothing else.
 *
 * Deliberately separate from client_open(): a collision attempt is a client
 * MID-registration, and the refusal is answered with "*" as the target because
 * it has no nickname yet (RFC 2812 3.3, and the reason the line parses for a
 * client that is still registering). Sending the NICK here would hide it inside
 * a helper, and a helper that sent it would be a second place a scenario could
 * send the same claim twice -- which is exactly how the accounting assertion at
 * the end of this file first came to count three refusals instead of two. */
static void client_connect(test_client_t *c, nf_node_t *node)
{
    g_opened++;
    TF_CHECK_MSG(tc_connect(c, node->port) == 0, "tc_connect failed");
}

static void client_join(client_t *cl, const char *channel)
{
    char line[128];
    char needle[160];
    size_t from = open_window(cl);
    size_t end;

    (void)snprintf(line, sizeof line, "JOIN %s", channel);
    /* Full line PREFIX, not a bare " 366 ": this node prints a 329 with a
     * ten-digit creation timestamp on every JOIN, so a bare three-digit needle
     * matches inside that number and the wait would be satisfied before the JOIN
     * had produced a 366 at all. */
    (void)snprintf(needle, sizeof needle, ":%s 366 %s ", BIN_NAME, cl->nick);
    TF_CHECK_MSG(tc_send(&cl->c, line) == 0, "tc_send(%s) failed", line);
    TF_CHECK_MSG(tc_expect(&cl->c, needle, T_IO_MS) == 0, "%s: no 366 after JOIN %s",
                 cl->nick, channel);
    end = drain(cl);
    expect_in_window(cl, from, end, line, needle);
}

/* How many connections this file opened. Compared against the node's own
 * `accepted=` so a scenario that silently opened one more than it meant to is
 * visible rather than absorbed. */
#define OPENED_5 5u

int main(void)
{
    nf_node_t node;
    client_t alice, bob, bobcase, dave, carol;
    size_t from, end;

    TF_CHECK(nf_spawn_binary(&node) == 0);
    TF_CHECK_MSG(nf_expect(&node, "loop_running:", T_READY_MS) == 0,
                 "the node never reported its loop armed");

    /* ---------------------------------------------------------------------
     * `bobcase` registers as "Bob" and `bob` registers as "bob". They are two
     * SEPARATE connections, taken in that order, and the order is not
     * cosmetic: once the registry folds they are the SAME name, so the second
     * would be refused with 433 while the first is connected -- which is
     * section 4 below, arriving early and for the wrong reason.
     *
     * So `Bob` is displayed and then QUITs before `bob` is taken. The sequence
     * is deliberate in the other direction too: a file that only ever used one
     * spelling could not tell "folds correctly" from "happened to be spelled the
     * same way as the query".
     * --------------------------------------------------------------------- */
    client_open(&alice, &node, "alice");
    client_open(&bobcase, &node, "Bob");

    /* =======================================================================
     * 1. THE DISPLAY CASE SURVIVES EVERY WAY A NICK IS PUT ON THE WIRE
     * ==================================================================== */
    /* First, because it is the half of the fix a "just lowercase conn_t::nick"
     * patch gets wrong while every lookup assertion still passes.
     *
     * The order inside the section is also load-bearing for DIAGNOSIS: the two
     * assertions that need no channel come first, so a node that folded the
     * stored nickname fails on the line that says so ("expected the exact line
     * ... Bob ...") rather than on some later JOIN whose 366 needle happened to
     * be built from the same field. */
    send_expect(&alice, "WHOIS Bob",
                ":irc.test 311 alice Bob Bob 127.0.0.1 * :Real Bob\r\n");

    /* 303 -- ISON answers with display values too, and it is a SET query, so a
     * node that folded here would list `bob` for a client that registered as
     * `Bob`, with no way for the client to tell the two apart. The query is a
     * third spelling on purpose: the resolution folds and the answer does not. */
    send_expect(&alice, "ISON BoB", ":irc.test 303 alice Bob :are online\r\n");

    /* "Bob" joins a channel alice created, so the roster holds both a capitalised
     * and a lowercase name and a node that rendered the folded form would be
     * visible rather than merely incorrect. alice is the channel's creator and so
     * is its op; bobcase is a plain member, and 353's groups are plain first,
     * then ops (7/Phase 4's order). */
    client_join(&alice, "#t");
    client_join(&bobcase, "#t");

    /* 353 -- the roster. Asked for directly with NAMES rather than read out of
     * bobcase's own JOIN, so the window below contains nothing but the answer to
     * it.
     *
     * Each presence is a whole exact line and each absence is that same line with
     * the one word folded, and it is the PAIR that makes this a display assertion
     * rather than another lookup assertion: a node that rendered `bob` satisfies
     * neither the presence nor the folded-uppercase absence. */
    from = open_window(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "NAMES #t") == 0, "tc_send failed");
    end = drain(&alice);
    expect_in_window(&alice, from, end, "353, the plain-member group",
                     ":irc.test 353 alice = #T Bob\r\n");
    expect_absent_in_window(&alice, from, end, "353, folded to lowercase",
                            ":irc.test 353 alice = #T bob\r\n");
    expect_absent_in_window(&alice, from, end, "353, folded to uppercase",
                            ":irc.test 353 alice = #T BOB\r\n");

    /* The message PREFIX. Read from conn_t::nick, so it is the one place a node
     * that had folded the STORED nickname would be wrong in a way a client shows
     * to a human rather than parses. */
    {
        size_t f1 = open_window(&alice);
        size_t e1;

        TF_CHECK_MSG(tc_send(&bobcase.c, "PRIVMSG #T :mixed case") == 0,
                     "tc_send failed");
        /* Sender first, and the reason is ordering rather than politeness:
         * bobcase and alice are different sockets and nothing orders a PING on
         * one against a PRIVMSG on the other. bobcase's PONG cannot be written
         * until the dispatch carrying his command has fanned the message out, so
         * by the time it is in hand alice's copy is already queued and her own
         * drain below closes her window strictly after it. Draining alice first
         * would close her window while the delivery was still outstanding --
         * a false pass. */
        (void)drain(&bobcase);
        e1 = drain(&alice);
        expect_in_window(&alice, f1, e1, "the PRIVMSG prefix",
                         ":Bob!Bob@127.0.0.1 PRIVMSG #T :mixed case\r\n");
        expect_absent_in_window(&alice, f1, e1,
                                "a source prefix folded to lowercase", ":bob!");
        expect_absent_in_window(&alice, f1, e1,
                                "a source prefix folded to uppercase", ":BOB!");
    }

    /* 352 -- WHO over the channel. The same field, a different numeric and a
     * different handler from 353, so the two cannot both be right by accident.
     * The flags are `H` (here) because bobcase has sent no AWAY. */
    {
        char want[256];

        (void)snprintf(want, sizeof want,
                       ":irc.test 352 alice #T Bob %s %s Bob H :0 Real Bob\r\n",
                       OBSERVED_HOST, BIN_NAME);
        from = open_window(&alice);
        TF_CHECK_MSG(tc_send(&alice.c, "WHO #t") == 0, "tc_send failed");
        end = drain(&alice);
        expect_in_window(&alice, from, end, "352 for Bob", want);
        expect_absent_in_window(&alice, from, end, "352 folded to lowercase",
                                "#T bob 127.0.0.1");
        expect_absent_in_window(&alice, from, end, "352 folded to uppercase",
                                "#T BOB 127.0.0.1");
    }

    /* The claimed hostname never reaches the wire. bobcase sent `USER Bob 0
     * *spoofed.example :...`, and every prefix assertion above is satisfied by
     * `:Bob!Bob@127.0.0.1` -- so without this the file would not distinguish a
     * node that built the prefix from the OBSERVED address from one that echoed
     * the client's own claim. */
    from = open_window(&bobcase);
    TF_CHECK_MSG(tc_send(&bobcase.c, "WHO #t") == 0, "tc_send failed");
    end = drain(&bobcase);
    expect_absent_in_window(&bobcase, from, end, "a claimed hostname",
                            CLAIMED_HOST);

    /* ---------------------------------------------------------------------
     * Bob gives the name up, and the wait for it is a deadline over an EOF --
     * never a sleep. The QUIT path releases the name (commands.c's handle_quit)
     * before the reaper closes the socket, so a clean FIN is the proof that the
     * name is free, and section 2's `PRIVMSG BOB` is about a name this node
     * holds rather than one that happens to be free.
     * --------------------------------------------------------------------- */
    TF_CHECK_MSG(tc_send(&bobcase.c, "QUIT :done") == 0, "tc_send failed");
    TF_CHECK_MSG(tc_expect_eof(&bobcase.c, T_IO_MS) == 0,
                 "the node did not close the QUIT-ed connection cleanly");
    /* And the name really is gone, not merely unreachable: a 401 is the only
     * honest way to say so, and it is asserted rather than inferred from the
     * 433 that comes next. */
    send_expect(&alice, "WHOIS Bob",
                ":irc.test 401 alice Bob :No such nick/channel\r\n");

    /* Now the same name, taken in the other case. Everything below is about the
     * registry folding: bob holds `bob` and must be found by `BOB`, and nobody
     * else may hold either spelling while he does. */
    client_open(&bob, &node, "bob");

    /* =======================================================================
     * 2. `PRIVMSG BOB :hi there` REACHES THE CLIENT REGISTERED AS `bob`
     * ==================================================================== */
    /* The headline symptom. 2.1 and RFC 2812 2.3.1 both make the name
     * case-insensitive, so the recipient is demonstrably connected and a 401
     * would be the node refusing a message whose recipient is there.
     *
     * The TARGET in the delivered line is `bob`, not the `BOB` alice typed: the
     * node echoes the nickname the holder chose, which is 2.1's per-server
     * identity and not a normalisation of alice's spelling. So this one line
     * asserts both halves of the fix -- resolution folded, rendering did not.
     *
     * A body with a space, so 3.2's formatter colons it. The colon is not what
     * is under test here and pinning the single-word form would bake in a detail
     * this file has no business asserting. */
    {
        size_t f1 = open_window(&bob);
        size_t e1;

        TF_CHECK_MSG(tc_send(&alice.c, "PRIVMSG BOB :hi there") == 0,
                     "tc_send failed");
        /* Sender first, for the cross-socket ordering reason given in section 1:
         * alice's PONG cannot be written until the dispatch carrying her command
         * has delivered the message, so draining her first closes bob's window
         * only after the delivery is already queued on it. */
        (void)drain(&alice);
        e1 = drain(&bob);
        expect_in_window(&bob, f1, e1, "PRIVMSG addressed as BOB",
                         ":alice!alice@127.0.0.1 PRIVMSG bob :hi there\r\n");
    }

    /* =======================================================================
     * 3. `WHOIS BOB` FINDS `bob`
     * ==================================================================== */
    /* A different command, a different handler and a different numeric, because
     * a registry that resolved PRIVMSG but not WHOIS would pass the check above
     * alone -- and WHOIS is how a client asks whether somebody is there at all,
     * so a 401 here is a client that believes a connected user is offline. */
    send_expect(&alice, "WHOIS BOB",
                ":irc.test 311 alice bob bob 127.0.0.1 * :Real bob\r\n");

    /* =======================================================================
     * 4. THE CLAIM THAT ACTUALLY VIOLATES 2.1: `BOB` IS REFUSED WHILE `bob`
     *    IS HELD, AND THE INCUMBENT KEEPS THE NAME
     * ==================================================================== */
    /* This is the part of the issue that is a CORRECTNESS bug rather than an
     * inconvenience. Before the fold, dave's `NICK BOB` SUCCEEDED: `bob` and
     * `BOB` were different keys, so a node whose whole identity scheme is
     * nick@server was running two users whose names differ only in case, and
     * 2.1's "uniqueness is enforced per server, no policy and no lock" was
     * false. test_dup_nick proves the same claim for the exact spelling; this
     * proves it for the case that got through. */
    client_connect(&dave.c, &node);
    send_expect(&dave, "NICK BOB",
                ":irc.test 433 * BOB :Nickname is already in use\r\n");

    /* Only one of the two can be HELD, which is a stronger statement than "one
     * claim was refused": a node that refused the second connection and then
     * quietly handed it the name anyway would have satisfied the check above.
     * `ISON BOB` resolves every holder of that name and renders each one in its
     * own case, so on a node that let both through this answers with two names
     * and the needle -- which reaches the closing CRLF -- does not match. */
    send_expect(&alice, "ISON BOB", ":irc.test 303 alice bob :are online\r\n");

    /* The refused client is not wedged: a 433 must leave it able to register. */
    TF_CHECK_MSG(tc_send(&dave.c, "NICK dave") == 0, "tc_send failed");
    TF_CHECK_MSG(tc_send(&dave.c, "USER dave 0 *spoofed.example :Real dave") == 0,
                 "tc_send failed");
    TF_CHECK_MSG(tc_expect(&dave.c, " 001 dave :Welcome", T_IO_MS) == 0,
                 "the refused client could not register under a free name");
    TF_CHECK_MSG(tc_send(&dave.c, "PING :dave-drain") == 0, "tc_send failed");
    TF_CHECK_MSG(tc_expect(&dave.c, "PONG irc.test dave-drain", T_IO_MS) == 0,
                 "no PONG after dave registered");

    /* And the INCUMBENT kept it: bob re-asserting his own name is silent, which
     * is only possible if dave's refused claim did not take it. Counted inside
     * a window, so the count is about this exchange rather than the session. */
    {
        size_t f1 = open_window(&bob);
        size_t e1;

        TF_CHECK_MSG(tc_send(&bob.c, "NICK bob") == 0, "tc_send failed");
        e1 = drain(&bob);
        TF_CHECK_MSG(count_in_window(&bob, f1, e1, " 433 ") == 0,
                     "the incumbent got 433 for his own nickname (%zu in window): "
                     "the loser of a collision displaced the holder",
                     count_in_window(&bob, f1, e1, " 433 "));
    }

    /* =======================================================================
     * 5. THE HOLDER RE-ASSERTING HIS OWN NAME IN ANOTHER CASE IS SILENT
     * ==================================================================== */
    /* RFC 2812 3.2: a NICK to the name you already have changes nothing and
     * generates no error. With a folded registry, `BOB` IS the name bob holds,
     * so this must be silent too.
     *
     * This is its own section because it is the half of the change most likely
     * to be got wrong, and in the direction that is invisible until somebody
     * does it: a handler that still compared `want` against conn_t::nick with
     * strcmp would treat "BOB" as a rename, fall through to the claim, find the
     * name already held by THIS connection, and answer 433 to bob for the
     * nickname he is holding. A test that only checked the DUPLICATE case would
     * not see it, because dave's claim and bob's re-assertion end up at the same
     * lookup by opposite routes.
     *
     * What is asserted is silence plus STAYING PUT: the two checks below would
     * both fail if the NICK had been treated as a rename. */
    {
        size_t f1 = open_window(&bob);
        size_t e1;

        TF_CHECK_MSG(tc_send(&bob.c, "NICK BOB") == 0, "tc_send failed");
        e1 = drain(&bob);
        TF_CHECK_MSG(count_in_window(&bob, f1, e1, " 433 ") == 0,
                     "re-asserting your own nickname in another case answered 433 "
                     "(%zu in window)",
                     count_in_window(&bob, f1, e1, " 433 "));
        TF_CHECK_MSG(count_in_window(&bob, f1, e1, " 001 ") == 0,
                     "re-asserting your own nickname re-sent the welcome burst "
                     "(%zu in window): a client treats 001 as \"I am connected\" "
                     "and would be pushed back into its connect path",
                     count_in_window(&bob, f1, e1, " 001 "));
    }
    /* Still `bob` on the wire, and still reachable by the lowercase spelling. A
     * rename to `BOB` would satisfy the silence above and fail both of these. */
    send_expect(&alice, "WHOIS bob",
                ":irc.test 311 alice bob bob 127.0.0.1 * :Real bob\r\n");
    send_expect(&alice, "ISON BOB", ":irc.test 303 alice bob :are online\r\n");

    /* =======================================================================
     * 6. A HELD NAME IS RELEASED AND THE UPPERCASE SPELLING TAKES IT -- AND
     *    THE LOWERCASE SPELLING IS THEN REFUSED
     * ==================================================================== */
    /* The other direction, and the half a "refuse duplicates" fix can get wrong:
     * folding on the way IN is not enough if the release cannot find the entry
     * again. bob hands the name back; carol claims it as `BOB`, which must
     * succeed because the name is free; and bob must then be refused `bob`,
     * because it is the same name carol now holds.
     *
     * The rename is confirmed on the node's observable output first, so the
     * next step cannot pass for the wrong reason: if bob had not actually given
     * the name up, carol's success would prove nothing about release. */
    TF_CHECK_MSG(tc_send(&bob.c, "NICK bob2") == 0, "tc_send failed");
    TF_CHECK_MSG(nf_expect(&node, "from=bob to=bob2", T_IO_MS) == 0,
                 "bob did not rename, so the release this section checks did not "
                 "happen");
    client_connect(&carol.c, &node);
    TF_CHECK_MSG(tc_send(&carol.c, "NICK BOB") == 0, "tc_send failed");
    TF_CHECK_MSG(tc_send(&carol.c, "USER carol 0 *spoofed.example :Real carol") ==
                     0,
                 "tc_send failed");
    TF_CHECK_MSG(tc_expect(&carol.c, " 001 BOB :Welcome", T_IO_MS) == 0,
                 "the released name could not be claimed in another case, so the "
                 "registry will not accept the spelling a user happens to prefer");
    /* Silence about the claim itself, checked as a negative rather than inferred
     * from the 001: a NICK that was refused and then somehow taken would answer
     * 433 AND register. */
    TF_CHECK_MSG(tc_send(&carol.c, "PING :carol-drain") == 0, "tc_send failed");
    TF_CHECK_MSG(tc_expect(&carol.c, "PONG irc.test carol-drain", T_IO_MS) == 0,
                 "no PONG after carol registered");
    TF_CHECK_MSG(tf_count(tc_buffer(&carol.c), " 433 ") == 0,
                 "carol was refused the free name (%zu refusals): the release "
                 "left an entry behind",
                 tf_count(tc_buffer(&carol.c), " 433 "));

    /* carol's chosen case is what she is shown as, in her own 001 above and in
     * a 311 addressed by the OTHER spelling -- which is the same name. The
     * <user> field is `carol`, not `BOB`: the nickname is the case-sensitive
     * display value and the username is untouched by any of this. */
    send_expect(&alice, "WHOIS bob",
                ":irc.test 311 alice BOB carol 127.0.0.1 * :Real carol\r\n");
    send_expect(&alice, "ISON bob", ":irc.test 303 alice BOB :are online\r\n");

    /* And bob cannot have his own spelling back, even though nobody holds it
     * byte-for-byte. This is the reverse half of section 4: between them the two
     * directions say that `bob` and `BOB` are ONE name rather than two slots. */
    send_expect(&bob, "NICK bob", ":irc.test 433 bob2 bob :Nickname is already "
                                "in use\r\n");

    /* =======================================================================
     * The node's own accounting
     * ==================================================================== */
    /* Exactly two claims were refused in this file -- dave's `NICK BOB` and
     * bob's `NICK bob` -- and exactly two. Counting them is what says that
     * bob's own differently-cased re-assertion in section 5 was SILENT rather
     * than merely unobserved on the wire: a third refusal would be a 433 the
     * test never waited for, and a second for either refused claim would mean
     * the claim was attempted twice.
     *
     * Read after nf_stop(), which drains the child's output. The node's stdout
     * is a pipe that is only read when something asks for it, so counting
     * before the child exits would count whatever happened to be pumped
     * already -- a number that depends on the scheduler. */
    TF_CHECK_MSG(nf_stop(&node) == 0, "node did not exit cleanly");
    TF_CHECK_MSG(tf_count(node.out, "reason=in_use") == 2,
                 "the node refused %zu nickname claims, expected 2",
                 tf_count(node.out, "reason=in_use"));
    /* n_reply_refused is documented in reply.c as a BUG REPORT rather than a
     * metric: a non-zero value is what a refused render or an unrepresentable
     * parameter would produce with no wire assertion above failing. */
    TF_CHECK_MSG(nf_expect_u64(&node, "reply_refused=", 0, T_IO_MS) == 0,
                 "reply_refused is not 0: a reply the node could not render was "
                 "dropped instead of sent");
    TF_CHECK_MSG(nf_expect_u64(&node, "accepted=", OPENED_5, T_IO_MS) == 0,
                 "accepted should be %u", OPENED_5);
    TF_CHECK_MSG(g_opened == OPENED_5, "the test opened %zu connections, "
                 "expected %u -- the accounting assertions above assume this",
                 g_opened, OPENED_5);

    tc_close(&alice.c);
    tc_close(&bob.c);
    tc_close(&bobcase.c);
    tc_close(&dave.c);
    tc_close(&carol.c);
    nf_free(&node);
    tf_done("nick_case");
    return 0;
}
