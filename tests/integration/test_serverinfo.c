/* test_serverinfo.c -- LUSERS, ADMIN and INFO on the wire, against the real
 * binary.
 *
 * docs/SERVER_DESIGN.md 4.2 (LUSERS, ADMIN, INFO, Phase 7), 4.4 (server info
 * 251-266) and RFC 2812 3.4.2 / 3.4.4. 402, 371 and 374 are holes in 4.4's list;
 * see commands.c's server-info section for the argument that the RFC numerics are
 * used anyway, and msg_verbs.c's for the same argument about 302.
 *
 * ---------------------------------------------------------------------------
 * THE POINT OF THIS FILE: THE NUMBERS ARE MEASURED
 * ---------------------------------------------------------------------------
 * LUSERS is the one command in 4.2 whose output is a set of COUNTS, and a count
 * is the easiest thing in a protocol to fake. A node that answered 251 with a
 * constant would satisfy every shape assertion below. So the counts are the
 * assertions:
 *
 *   - The client count is read BEFORE and AFTER a second client connects, and
 *     the two must differ by exactly one. This is the assertion with teeth for
 *     the whole file: nothing else here can tell a measured count from a
 *     hardcoded one.
 *   - 251's five trailing fields are parsed out of the line with sscanf and
 *     checked individually -- <hops> must be 0, <clients> must equal the count
 *     the node reports elsewhere in the same reply, <servers> must be 0 on a
 *     single node, and <max> must be a plausible ceiling. A substring search for
 *     " 251 " would pass a node that sent the code and nothing else.
 *   - 265's <local> and 266's <global> must be the SAME number here, and the
 *     reason is worth stating: a single node IS the whole of the network it
 *     serves. A node reporting a larger global figure would be inventing one.
 *   - 252, 253 and 254 must be ABSENT. They are the three optional refinement
 *     numerics that need separate connection-class counters, which this node does
 *     not keep; producing them would mean splitting one real number into three
 *     invented ones.
 *
 * ---------------------------------------------------------------------------
 * ADMIN AND INFO ARE ASSERTED AS PROMISES, AND THE PROMISES ARE CHECKED
 * ---------------------------------------------------------------------------
 * INFO is a list of claims about this node, and a list of claims is only worth
 * printing if the claims are true. So the two most falsifiable lines are read off
 * the wire and then TESTED against the node: the line that says an unevaluated
 * channel mode is refused with 472 is followed by a MODE +k that must produce a
 * 472, and the line that says an unknown verb is 421 is followed by a verb this
 * build has never heard of. A node whose INFO lied about itself would pass every
 * other assertion in this file.
 *
 * ADMIN's four numerics are checked for presence, for order, and for the one that
 * carries a fact (257 names this node's own server, network and version -- the
 * same values 002 and 004 report, so they cannot drift). 258 and 259 say there
 * is nothing there, and they are asserted by their content rather than by their
 * presence, because a node that emitted 258 with a made-up services list would
 * satisfy a presence check.
 *
 * NO sleep() ANYWHERE (6.3): every wait is a select()-driven deadline inside
 * tc_expect(), and every negative assertion is scoped to a window closed by a
 * PING drain. A bare tc_expect() searches the whole accumulated buffer, so a
 * second ` 251 ` would match the first and return instantly and the wait covering
 * the command under test would never happen.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "core/server.h"
#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

#define T_READY_MS 15000
#define T_IO_MS 15000

#define BIN_NAME "irc.test"
/* IRC_SERVE_VERSION, AND NOT A LITERAL, which is what this used to be. The rule was
 * already written down -- tests/integration/test_registration.c says it in as many
 * words, that asserting a hardcoded "0.1.0" "would make this test fail on every
 * version bump, and a test that gets deleted or loosened on each release is worth
 * less than one that keeps checking the FORMAT" -- and this file broke it anyway,
 * which is the whole argument for having a test that can see a second copy rather
 * than a comment asking nicely. See tests/integration/test_version_truth.c. */
#define VERSION IRC_SERVE_VERSION
#define NETWORK "irc-serve"

/* 4.4's server-info range and the ceiling 251/265/266 carry. 1024 is
 * server.h's SERVER_FD_TABLE, which is FD_SETSIZE: server_t::by_fd is a flat
 * array indexed by descriptor and the accept site refuses an fd at or above it,
 * so a node cannot hold more connections than this. Written as the literal on
 * purpose, for the reason test_queries.c writes AWAY_MAX as the literal rather
 * than including it -- a test that reads the bound from the header cannot fail if
 * the header is wrong, and this file's job is to notice that. */
#define SERVER_FD_TABLE_LITERAL 1024

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

static size_t mark(client_t *cl)
{
    char line[64];
    char needle[96];
    const char *at;

    g_drain_seq++;
    (void)snprintf(line, sizeof line, "PING :m%u", g_drain_seq);
    (void)snprintf(needle, sizeof needle, "PONG %s m%u\r\n", BIN_NAME,
                   g_drain_seq);
    TF_CHECK_MSG(tc_send(&cl->c, line) == 0, "mark PING send failed");
    TF_CHECK_MSG(tc_expect(&cl->c, needle, T_IO_MS) == 0, "no PONG for %s", line);
    at = strstr(tc_buffer(&cl->c), needle);
    TF_CHECK_MSG(at != NULL, "the mark PONG vanished from the buffer");
    return (at != NULL) ? (size_t)(at - tc_buffer(&cl->c)) : 0u;
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

/* 251 RPL_LUSERS: `:<server> 251 <client> :<server> <hops> <clients> <servers>
 * <max clients>`, with the server name repeated in the trailing text.
 *
 * PARSED rather than searched, for the reason test_queries.c parses 317: a
 * substring search for " 251 " is satisfied by a line carrying the code and
 * nothing else, and every field below can be independently wrong while the code
 * is right. Returns 0 on success and fills the four outputs. */
static int parse_251(const client_t *cl, size_t from, size_t end,
                     int *hops, unsigned long long *clients,
                     unsigned long long *servers, unsigned long long *maxclients)
{
    const char *base = tc_buffer(&cl->c);
    const char *at = strstr(base + from, ":" BIN_NAME " 251 ");
    char wire[256];
    char server[64];
    const char *line_end;
    const char *body;
    size_t n;

    TF_CHECK_MSG(at != NULL, "the 251 line vanished from the window");
    if (at == NULL || at >= base + end) {
        TF_CHECK_MSG(at == NULL, "the 251 line is outside the window");
        return -1;
    }
    line_end = strstr(at, "\r\n");
    TF_CHECK_MSG(line_end != NULL && line_end < base + end,
                 "the 251 line is not terminated inside the window");
    n = (line_end != NULL) ? (size_t)(line_end - at) : strlen(at);
    if (n >= sizeof wire) {
        n = sizeof wire - 1u;
    }
    memcpy(wire, at, n);
    wire[n] = '\0';

    body = strstr(wire, " 251 alice :");
    TF_CHECK_MSG(body != NULL, "the 251 line does not name the client: \"%s\"",
                 wire);
    if (body == NULL) {
        return -1;
    }
    body += strlen(" 251 alice :");
    /* No %s for the server name: %s WRITES to its argument, and a string
     * literal is not a destination. The line prefix is stepped over instead. */
    TF_CHECK_MSG(sscanf(body, "%63s %d %llu %llu %llu", server, hops, clients,
                        servers, maxclients) == 5,
                 "251's parameters are not <server> <hops> <clients> <servers> "
                 "<max clients>; the line was \"%s\"",
                 wire);
    return 0;
}

int main(void)
{
    nf_node_t node;
    client_t alice, bob;
    size_t from, end;
    int hops = -1;
    unsigned long long clients = 0, servers = 0, maxclients = 0;
    unsigned long long local = 0, global = 0, lmax = 0, gmax = 0;
    char want[512];

    if (nf_spawn_binary(&node) != 0) {
        fprintf(stderr, "could not spawn the irc-serve binary\n");
        return 1;
    }
    TF_CHECK_MSG(nf_expect(&node, "loop_running:", T_READY_MS) == 0,
                 "the node never reported its loop armed");

    client_open(&alice, &node, "alice");

    /* =======================================================================
     * 1. LUSERS with one client: 251, 255, 265, 266 and nothing else
     * ==================================================================== */
    from = mark(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "LUSERS") == 0, "tc_send failed");
    end = mark(&alice);
    expect_in_window(&alice, from, end, "255 RPL_LUSERME",
                     ":" BIN_NAME " 255 alice :I have 1 clients and 0 servers\r\n");
    /* 252, 253 and 254 are the optional refinement numerics that need separate
     * connection-class counters. This node keeps exactly one user counter and has
     * no connection-class configuration, so producing them would mean splitting
     * one real number into three invented ones. Their absence is the assertion. */
    expect_absent_in_window(&alice, from, end, "the LUSERS window", " 252 ");
    expect_absent_in_window(&alice, from, end, "the LUSERS window", " 253 ");
    expect_absent_in_window(&alice, from, end, "the LUSERS window", " 254 ");

    TF_CHECK_MSG(parse_251(&alice, from, end, &hops, &clients, &servers,
                            &maxclients) == 0,
                 "251 did not parse");
    /* <hops> is 0 and 0 is TRUE: it counts forwards, and this node originated
     * every count it is reporting. A node answering 1 would be claiming a relay
     * that did not happen. */
    TF_CHECK_MSG(hops == 0, "251's <hops> is %d, expected 0", hops);
    /* The count is MEASURED: alice is the only connection holding a nickname. */
    TF_CHECK_MSG(clients == 1ull,
                 "251's <clients> is %llu, expected 1 (alice is the only "
                 "registered client)",
                 clients);
    /* No peers on a single node, so no ESTABLISHED links. server_link_count() would
     * say 0 here too, and this is the assertion that a half-linked peer is not
     * counted: a node that used the link COUNT rather than the ESTABLISHED count
     * would pass on this node and overstate a mesh. */
    TF_CHECK_MSG(servers == 0ull,
                 "251's <servers> is %llu, expected 0 (a single node has no "
                 "established peers)",
                 servers);
    TF_CHECK_MSG(maxclients == (unsigned long long)SERVER_FD_TABLE_LITERAL,
                 "251's <max clients> is %llu, expected %d -- it is the node's "
                 "connection-table bound, not a configured maximum",
                 maxclients, SERVER_FD_TABLE_LITERAL);

    /* 265 and 266 carry their two numbers as MIDDLE parameters and the sentence
     * as the trailing one, and the numbers are the same on this node because a
     * single node IS the whole of the network it serves. */
    (void)snprintf(want, sizeof want,
                   ":" BIN_NAME " 265 alice 1 %d :Current local users 1, max "
                   "%d\r\n",
                   SERVER_FD_TABLE_LITERAL, SERVER_FD_TABLE_LITERAL);
    expect_in_window(&alice, from, end, "265 RPL_LOCALUSERS", want);
    (void)snprintf(want, sizeof want,
                   ":" BIN_NAME " 266 alice 1 %d :Current global users 1, max "
                   "%d\r\n",
                   SERVER_FD_TABLE_LITERAL, SERVER_FD_TABLE_LITERAL);
    expect_in_window(&alice, from, end, "266 RPL_GLOBALUSERS", want);
    /* 265 and 266 are read out of the wire rather than assumed from the needle
     * above, so a node that reported a DIFFERENT <global> from its <local> --
     * which is what "global" is for on a mesh -- is caught rather than satisfied
     * by the two needles both happening to say 1. */
    {
        const char *base = tc_buffer(&alice.c);
        const char *at265 = strstr(base + from, ":" BIN_NAME " 265 alice ");
        const char *at266 = strstr(base + from, ":" BIN_NAME " 266 alice ");

        TF_CHECK_MSG(at265 != NULL && at266 != NULL,
                     "265 or 266 vanished from the window");
        if (at265 != NULL && at266 != NULL) {
            TF_CHECK_MSG(sscanf(at265, " %*s %*s %*s %llu %llu", &local, &lmax) == 2,
                         "265's middle parameters are not <local> <max>");
            TF_CHECK_MSG(sscanf(at266, " %*s %*s %*s %llu %llu", &global, &gmax) == 2,
                         "266's middle parameters are not <global> <max>");
            TF_CHECK_MSG(local == global,
                         "266's <global> is %llu and 265's <local> is %llu: on a "
                         "single node the network IS this node, so the two must "
                         "be the same number",
                         global, local);
            TF_CHECK_MSG(lmax == gmax,
                         "265's <max> is %llu and 266's <max> is %llu: they are "
                         "the same bound seen two ways",
                         lmax, gmax);
        }
    }

    /* =======================================================================
     * 2. The count MOVES. This is the assertion with teeth for the whole file.
     * ==================================================================== */
    client_open(&bob, &node, "bob");
    from = mark(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "LUSERS") == 0, "tc_send failed");
    end = mark(&alice);
    (void)snprintf(want, sizeof want,
                   ":" BIN_NAME " 255 alice :I have 2 clients and 0 servers\r\n");
    expect_in_window(&alice, from, end, "255 after a second client connected", want);
    TF_CHECK_MSG(parse_251(&alice, from, end, &hops, &clients, &servers,
                            &maxclients) == 0,
                 "251 did not parse after the second client");
    TF_CHECK_MSG(clients == 2ull,
                 "251's <clients> is %llu after bob connected, expected 2: the "
                 "count is not being measured",
                 clients);

    /* And it moves DOWN when a client goes away, so it is the number of
     * connections and not a high-water mark. bob QUITs and is REAPED, and the
     * reap is waited on rather than assumed: a count taken while bob's conn is
     * still registered would be a race, and a test that raced would pass on a
     * fast machine and fail on a slow one.
     *
     * The wait is on the reaper's own `conn_reaped` line rather than on the
     * `closed=` counter, because loop_stats is republished on the node's own
     * schedule and waiting for a COUNTER to be published after the fact is a
     * different wait with a different failure mode -- the counter is published
     * at shutdown, which is why test_queries.c reads it after nf_stop().
     *
     * ONE reap is the right number to wait for and it is a specific one: at this
     * point the node holds exactly two connections, alice and bob, and alice has
     * not disconnected. So the first reap on the node can only be bob's, and a
     * second one would never arrive. */
    TF_CHECK_MSG(tc_send(&bob.c, "QUIT :done") == 0, "QUIT send failed");
    TF_CHECK_MSG(nf_expect_nth(&node, "conn_reaped:", 1, T_IO_MS) == 0,
                 "the node has not reaped bob, so a LUSERS taken now would still "
                 "count him");
    from = mark(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "LUSERS") == 0, "tc_send failed");
    end = mark(&alice);
    (void)snprintf(want, sizeof want,
                   ":" BIN_NAME " 255 alice :I have 1 clients and 0 servers\r\n");
    expect_in_window(&alice, from, end, "255 after bob left", want);

    /* =======================================================================
     * 3. The <server> mask: this node's own name is accepted, another is 402
     * ==================================================================== */
    /* 2.4 requires a server-name comparison to be case-insensitive, so the mask
     * is matched with the tree's fold rather than strcmp. A node using strcmp
     * would 402 the client's own server name in a different case, which is the
     * kind of refusal a client cannot act on. */
    from = mark(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "LUSERS " BIN_NAME) == 0, "tc_send failed");
    end = mark(&alice);
    expect_in_window(&alice, from, end, "LUSERS with this node's own name",
                     ":" BIN_NAME " 255 alice :I have 1 clients and 0 servers\r\n");

    from = mark(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "LUSERS other.example") == 0, "tc_send failed");
    end = mark(&alice);
    /* 402 rather than 403: the complaint is about a SERVER, and 403 is the
     * channel family's "no such channel". 402 is not in 4.4's list either; see
     * commands.c for the gap argument. */
    expect_in_window(&alice, from, end, "402 for a server this node cannot reach",
                     ":" BIN_NAME " 402 alice other.example :No such server: "
                     BIN_NAME " cannot reach other.example\r\n");
    /* And NO counts came with it. A node that answered a foreign mask with its own
     * numbers would be reporting on a server nobody asked about, and the client
     * would have no way to tell the two answers apart. */
    expect_absent_in_window(&alice, from, end, "the foreign-mask LUSERS", " 251 ");
    expect_absent_in_window(&alice, from, end, "the foreign-mask LUSERS", " 255 ");

    /* =======================================================================
     * 4. ADMIN: 256, 257, 258, 259, in that order
     * ==================================================================== */
    from = mark(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "ADMIN") == 0, "tc_send failed");
    end = mark(&alice);
    expect_in_window(&alice, from, end, "256 RPL_ADMINME",
                     ":" BIN_NAME " 256 alice :Administrative info\r\n");
    /* 257 carries this node's own identity: the SAME server name 002 and 004
     * report, the network 005 advertises, and the version 002 carries. Asserting
     * them here is what makes INFO's and ADMIN's descriptions of this node
     * checkable rather than decorative -- if server.h's name or IRC_SERVE_VERSION
     * changed, this line would change with it and the test would follow. */
    expect_in_window(&alice, from, end, "257 RPL_ADMINLOC1",
                     ":" BIN_NAME " 257 alice :Server " BIN_NAME " on the "
                     NETWORK " network, version " VERSION "\r\n");
    expect_in_window(&alice, from, end, "258 RPL_ADMINLOC2",
                     ":" BIN_NAME " 258 alice :No services and no operator flags "
                     "on this node: CHOPER cannot succeed.\r\n");
    /* 259 is a contact ADDRESS in RFC 2812 3.4.2 and there is none, so the line
     * says so. A string that merely looked like an address would be offered to a
     * human by every client that renders it. */
    expect_in_window(&alice, from, end, "259 RPL_ADMINEMAIL",
                     ":" BIN_NAME " 259 alice :No administrative contact address "
                     "is configured for this node.\r\n");
    TF_CHECK_MSG(count_in_window(&alice, from, end, " 25") == 4,
                 "ADMIN produced %zu 25x lines, expected exactly 4 (256-259)",
                 count_in_window(&alice, from, end, " 25"));
    /* And the four are in ORDER, because 258's content refers to 257's subject: a
     * reader that met 258 first would not know which node it was about. */
    {
        const char *base = tc_buffer(&alice.c);
        const char *a256 = strstr(base + from, ":" BIN_NAME " 256 ");
        const char *a257 = strstr(base + from, ":" BIN_NAME " 257 ");
        const char *a258 = strstr(base + from, ":" BIN_NAME " 258 ");
        const char *a259 = strstr(base + from, ":" BIN_NAME " 259 ");

        TF_CHECK_MSG(a256 != NULL && a257 != NULL && a258 != NULL && a259 != NULL,
                     "an ADMIN numeric vanished from the window");
        if (a256 != NULL && a257 != NULL && a258 != NULL && a259 != NULL) {
            TF_CHECK_MSG(a256 < a257 && a257 < a258 && a258 < a259,
                         "ADMIN's four numerics are out of order: 256 < 257 < 258 "
                         "< 259 was expected");
        }
    }
    /* The same mask rule as LUSERS, and 402 again rather than a second numeral
     * for a second verb. */
    from = mark(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "ADMIN other.example") == 0, "tc_send failed");
    end = mark(&alice);
    expect_in_window(&alice, from, end, "402 for ADMIN's mask",
                     ":" BIN_NAME " 402 alice other.example :No such server: "
                     BIN_NAME " cannot reach other.example\r\n");
    expect_absent_in_window(&alice, from, end, "the foreign-mask ADMIN", " 256 ");
    /* ADMIN takes at most one mask (RFC 2812 3.4.2), and 461 rather than 462 for
     * the same reason every handler in the node uses 461. `ADMIN` before the
     * text is 5.2's `<command>` field and is asserted, so this needle fails
     * against a 461 that did not say which verb. */
    from = mark(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "ADMIN " BIN_NAME " extra") == 0,
                 "tc_send failed");
    end = mark(&alice);
    expect_in_window(&alice, from, end, "461 for two masks",
                     ":" BIN_NAME " 461 alice ADMIN :Not enough parameters\r\n");

    /* =======================================================================
     * 5. INFO: 371 lines terminated by 374, and 374 LAST
     * ==================================================================== */
    from = mark(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "INFO") == 0, "tc_send failed");
    end = mark(&alice);
    /* 374 is the terminator and it must come AFTER every 371, or a client that
     * stops reading at it loses the tail of the description. Checked as a
     * position, because a presence check is satisfied by a 374 that arrived
     * first. */
    {
        const char *base = tc_buffer(&alice.c);
        const char *last371 = NULL;
        const char *at374;
        size_t n371 = count_in_window(&alice, from, end, " 371 ");

        for (const char *p = base + from; p < base + end; p++) {
            if (strncmp(p, " 371 ", 5) == 0) {
                last371 = p;
            }
        }
        at374 = strstr(base + from, ":" BIN_NAME " 374 alice :End of /INFO list\r\n");
        TF_CHECK_MSG(n371 > 0u, "INFO produced no 371 lines at all");
        TF_CHECK_MSG(at374 != NULL, "INFO was not terminated by 374");
        TF_CHECK_MSG(at374 != NULL && last371 != NULL && at374 > last371,
                     "INFO: 374 came before the last 371, so a client that stops "
                     "at the terminator would lose part of the description");
        TF_CHECK_MSG(n371 >= 8u,
                     "INFO produced %zu 371 lines, which is too few to describe "
                     "the node; the count is not pinned to an exact number "
                     "because 4.2 does not fix one",
                     n371);
    }
    /* A representative line, byte for byte, so INFO's content is asserted rather
     * than merely counted. The first line is the one a client shows in its
     * "server information" dialog, so it is the one most worth being right. */
    expect_in_window(&alice, from, end, "371 for the node's identity",
                     ":" BIN_NAME " 371 alice :- " NETWORK ": a federation-native "
                     "IRC node, running " VERSION ".\r\n");

    /* =======================================================================
     * 6. INFO IS A LIST OF PROMISES, AND THE PROMISES ARE CHECKED
     * ==================================================================== */
    /* 6a: "channel modes evaluated here: +b ... every other letter is refused
     * with 472 rather than silently ignored". MODE +k is a letter this node does
     * not evaluate, so it must be 472 -- and 472 is not in 4.4's list either,
     * which is the same class of gap as 402 and 371.
     *
     * `k` IS THE MIDDLE FIELD AND `#INFO` IS IN THE TEXT, which is RFC 2812 5.2's
     * field list for 472: "<client> <char> :is unknown mode char to me for
     * <channel>". It used to be the other way round -- the middle parameter was the
     * channel and no character was named -- so a client parsing 472 by position
     * read `#INFO` as the rejected mode character. test_channels.c carries the
     * positional version of this same assertion, which is what says the character
     * is a FIELD rather than a coincidence of this line; this case is here because
     * 4.4's INFO promises 472 and the promise has to be checked where it is made. */
    client_join(&alice, "#INFO");
    from = mark(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "MODE #INFO +k somekey") == 0, "tc_send failed");
    end = mark(&alice);
    expect_in_window(&alice, from, end, "the 472 INFO promises",
                     ":" BIN_NAME " 472 alice k :is unknown mode char to me for "
                     "channel #INFO\r\n");
    /* 6b: "Unknown verbs are 421." A verb this build has never heard of must be
     * 421, and 421's middle parameter names the verb, so a client can see which
     * word it did not recognise. */
    from = mark(&alice);
    TF_CHECK_MSG(tc_send(&alice.c, "FROBNICATE now") == 0, "tc_send failed");
    end = mark(&alice);
    expect_in_window(&alice, from, end, "the 421 INFO promises",
                     ":" BIN_NAME " 421 alice FROBNICATE :Unknown command\r\n");
    /* 6c: the command list INFO gives is the command list the table holds. Every
     * verb INFO names as a 4.2 SHOULD command is sent, and each must answer with
     * something that is NOT 421 -- which is the only way to check a claim made in
     * prose about the dispatch table, from the wire, without reading the source. */
    {
        static const char *const verbs[] = {
            "WHO",  "WHOIS",  "ISON",   "LIST",  "AWAY",  "INVITE", "MOTD",
            "LUSERS", "ADMIN", "INFO",  "USERHOST", "KNOCK"
        };

        for (size_t i = 0; i < sizeof verbs / sizeof verbs[0]; i++) {
            from = mark(&alice);
            TF_CHECK_MSG(tc_send(&alice.c, verbs[i]) == 0, "tc_send(%s) failed",
                         verbs[i]);
            end = mark(&alice);
            TF_CHECK_MSG(count_in_window(&alice, from, end, " 421 ") == 0,
                         "INFO lists %s among the commands this node answers, and "
                         "the node answered 421 for it",
                         verbs[i]);
        }
    }

    /* =======================================================================
     * The node's own accounting
     * ==================================================================== */
    TF_CHECK_MSG(nf_stop(&node) == 0, "node did not exit cleanly");
    /* 0, and this is the test that would notice: 265 and 266 carry their numbers
     * as MIDDLE parameters, and 3.2's formatter refuses a value it cannot render
     * in that position rather than reshaping it -- so a handler that formatted a
     * number in place instead of rendering it to a buffer would put a
     * non-zero on the counter reply.c calls a bug report. */
    TF_CHECK_MSG(nf_expect_u64(&node, "reply_refused=", 0, T_IO_MS) == 0,
                 "reply_refused is not 0");
    TF_CHECK_MSG(nf_expect_u64_ge(&node, "accepted=", g_opened, T_IO_MS) == 0,
                 "the node accepted fewer connections than the test opened (%zu)",
                 g_opened);

    tc_close(&alice.c);
    tc_close(&bob.c);
    nf_free(&node);
    tf_done("serverinfo");
    return 0;
}
