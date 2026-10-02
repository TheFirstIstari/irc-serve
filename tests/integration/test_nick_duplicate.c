/* test_nick_duplicate.c -- 2.1's rename-the-loser, and 2.1's scoped `nick@server`
 * being ROUTED rather than recognised.
 *
 * docs/SERVER_DESIGN.md 2.1 ("Two servers may legitimately hold the same nick, so
 * the loser must be told on the wire, not silently renamed locally"; the scoped
 * identity `nick@server` and the "no lock: bob@a and bob@b are distinct registry
 * keys"), 4.3 (the S-verb list, and 4.3.1's SBURSTM `<server>` field), 4.4 (401),
 * 3.1 (the `message` row: "forward to that server") and 8 ("network-visible nick
 * ambiguity resolved by rename-the-loser plus a nick-registry broadcast").
 *
 * ---------------------------------------------------------------------------
 * WHAT WAS FALSE BEFORE THIS PASS, AND WHERE EACH CLAIM COMES FROM
 * ---------------------------------------------------------------------------
 *   1. THE ROUTING. 3.1's `message` row for a `nick@server` target has always said
 *      "forward to that server", and before Phase 9 nothing could: fanout_resolve()
 *      recognised the SHAPE of `nick@server` and produced a target with no
 *      destination, and msg_verbs.c answered 401 for it unconditionally -- a 401
 *      that was honest for a node that held no such user and a lie for a node with
 *      a peer that did. 2.1 is what makes the answer computable: a remote nick
 *      registry says which server holds a name, and a link says whether it can be
 *      reached. This is claim 1, and it is asserted on the WIRE by the far side
 *      receiving the text.
 *
 *   2. THE RENAME. 2.1's policy is a policy about DUPLICATES, and a duplicate
 *      needs a registry to be visible at all. With no registry a node could not
 *      know a peer held a name, so it could neither resolve `nick@server` nor
 *      decide it was the loser. This is claim 2, and it is asserted through four
 *      separate channels because a rename that lands in only one of them produces
 *      a mesh that looks renamed and is not.
 *
 * ---------------------------------------------------------------------------
 * WHY THE NAMES ARE irc.z AND irc.b, AND THAT IS THE WHO POINT OF THE FIXTURE
 * ---------------------------------------------------------------------------
 * fed_nickreg_local_loses() is a total order on the two server names, and the
 * rule is THE GREATER NAME IS RENAMED. So which node loses is decided by the
 * spelling of two #defines, and getting them the wrong way round would make this
 * file assert the wrong node's behaviour:
 *
 *      'z' > 'b'   so irc.z LOSES and irc.b KEEPS the name.
 *
 * That is why the DUPLICATE IS CREATED ON THE WINNER'S SIDE FIRST and the loser
 * discovers it second. A fixture that made the loser discover it first would test
 * the same code through a different path, and the path is the interesting part:
 * the loser here learns about the duplicate from a peer's SJOIN, not at the moment
 * it claims the name, which is the case that a "check at NICK time" implementation
 * gets wrong.
 *
 * ---------------------------------------------------------------------------
 * THE FIVE EFFECTS, AND WHERE EACH IS ASSERTED
 * ---------------------------------------------------------------------------
 * fed_nickreg_resolve_local() names them; the case checks each from a different
 * direction, because the four ways of getting the rename half-right all leave a
 * plausible-looking mesh:
 *
 *   1. THE DECISION          node irc.z's `nick_renamed: ... holder=irc.b`
 *   2. THE CLIENT            the renamed client receives `NICK zed_` and NOT 433
 *   3. THE LOCAL CHANNELS    a second client in the same channel sees the NICK
 *   4. THE MESH              node irc.b logs `fed_snick:` and REKEYS its roster --
 *                            which is the only assertion here that fails if
 *                            chan_remote_rename() is not called
 *   5. THE WINNER            irc.b's own `zed` is never renamed, which is the
 *                            convergence claim: exactly one of the two gives way
 *
 * ---------------------------------------------------------------------------
 * WHY NO FIXED sleep() ANYWHERE (6.3)
 * ---------------------------------------------------------------------------
 * Every wait is a deadline over a child's output or over a socket. The
 * interesting intervals -- "the SJOIN has not arrived yet", "the rename has not
 * been delivered yet" -- are bounded by assertions rather than slept through, and
 * a case that needed a sleep to see whether the rename worked would be unable to
 * tell a rename that took a millisecond from one that took a second.
 */
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "core/commands.h"
#include "core/server.h"
#include "federation/link.h"
#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

#define T_IO_MS 20000

#define SECRET "irc-serve-nickdup-secret"
#define NAME_Z "irc.z" /* the GREATER name: this node is the loser */
#define NAME_B "irc.b" /* the SMALLER name: this node keeps the duplicate */
/* The third node, and the reason this case is a THREE-node mesh. It is an
 * innocent bystander: it holds no user called anything of interest and it never
 * renames anybody. It exists for ONE assertion -- the one where a client names a
 * nick a peer holds but scopes it to a DIFFERENT peer -- and in a two-node mesh
 * that assertion cannot be made, because the two candidate answers coincide: with
 * one peer, "the server you named is not the holder" and "the server you named is
 * not a peer I can reach" are the same string. See the C3 case for the whole
 * argument. */
#define NAME_C "irc.c"

#define CHAN   "#DUP"
#define NICK_Z "zed"    /* claimed on irc.z, renamed to zed_ */
#define NICK_B "zed"    /* claimed on irc.b first, and kept */
#define NICK_W "watch"  /* a second client on irc.z, in the channel */
#define NICK_R "router" /* a client on irc.b, sends the scoped PRIVMSGs */

typedef struct {
    const char *peer_name; /* NULL: no peer configured */
    int         peer_port;
} child_cfg_t;

static child_cfg_t g_cfg;

static void child_setup(server_t *s)
{
    struct sockaddr_in addr;

    TF_CHECK_MSG(commands_dispatch != NULL,
                 "the client command surface is missing from the build");
    s->dispatch = commands_dispatch;
    TF_CHECK_MSG(fed_open(s, SECRET) == 0,
                 "fed_open() failed in the child; a node with an unopenable "
                 "federation module cannot reach any assertion in this test");
    s->on_tick = fed_tick;
    /* The shipped timeouts, not shortened ones. 2.1's policy contains no timeout
     * at all -- it runs on a registry entry, not on a clock -- so there is
     * nothing here to scale down, and using the shipped values is a statement
     * that the test is not measuring time. */
    fed_set_timeouts(2000, 2000, 900, 2700);

    if (g_cfg.peer_name != NULL && g_cfg.peer_port > 0) {
        memset(&addr, 0, sizeof addr);
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons((unsigned short)g_cfg.peer_port);
        TF_CHECK_MSG(fed_link_configure(s, g_cfg.peer_name,
                                        (const struct sockaddr *)&addr,
                                        (socklen_t)sizeof addr) != NULL,
                     "the child could not configure peer %s on port %d",
                     g_cfg.peer_name, g_cfg.peer_port);
    }
}

/* Register a client, and drain with a UNIQUE token so that every later wait on
 * this connection is against bytes read since -- tc_expect() searches the whole
 * accumulated buffer, so a shared token would let one drain satisfy the next. */
static void register_client(test_client_t *c, int port, const char *nick,
                            const char *token)
{
    char line[256];

    TF_CHECK_MSG(tc_connect(c, port) == 0, "%s could not connect", nick);
    (void)snprintf(line, sizeof line, "NICK %s", nick);
    TF_CHECK_MSG(tc_send(c, line) == 0, "NICK send failed for %s", nick);
    (void)snprintf(line, sizeof line, "USER %s 0 *spoofed :Real %s", nick, nick);
    TF_CHECK_MSG(tc_send(c, line) == 0, "USER send failed for %s", nick);
    TF_CHECK_MSG(tc_expect(c, " 001 ", T_IO_MS) == 0, "%s never registered", nick);
    (void)snprintf(line, sizeof line, "PING :%s", token);
    TF_CHECK_MSG(tc_send(c, line) == 0, "%s's drain PING send failed", nick);
    TF_CHECK_MSG(tc_expect(c, token, T_IO_MS) == 0,
                 "%s got no PONG carrying its drain token, so the lines before it "
                 "have not been read yet",
                 nick);
}

/* Everything this client has received since `mark`. The buffer only grows and is
 * NUL-terminated, so an offset into it is a valid C string -- and it is how a
 * "this name is NOT in the roster" assertion avoids matching a roster the same
 * client asked for earlier. */
static const char *since(const test_client_t *c, size_t mark)
{
    const char *buf = tc_buffer(c);

    return (tc_received(c) > mark) ? buf + mark : "";
}

/* A BRAND-NEW client asking for one roster, and the offset at which it begins.
 * A new client every time, because a connection that has never asked anything
 * cannot be satisfied by an answer it received earlier. */
static size_t ask_names(test_client_t *c, int port, const char *nick,
                        const char *token)
{
    char line[128];
    size_t mark;

    register_client(c, port, nick, token);
    mark = tc_received(c);
    (void)snprintf(line, sizeof line, "NAMES " CHAN);
    TF_CHECK_MSG(tc_send(c, line) == 0, "%s's NAMES send failed", nick);
    TF_CHECK_MSG(tc_expect(c, " 366 ", T_IO_MS) == 0,
                 "%s's NAMES of " CHAN " was never terminated, so a name missing "
                 "from the roster proves nothing: %s",
                 nick, tc_buffer(c));
    return mark;
}

/* How many times `nick` appears in a 353 as a WHOLE NAME, and the reason this
 * exists rather than tf_count() is that tf_count() counts substrings: `zed` occurs
 * twice in the roster ":watch zed" followed by "@zed_", because the second name
 * CONTAINS the first. The whole-name test is what makes "the rename created a
 * second entry for one user" a statement about the roster rather than about
 * spelling.
 *
 * THE NAME BYTES ARE letters, digits and '_', which is 2.1's charset for the
 * characters this case can produce and is a SUBSET of the full nick charset (which
 * also admits the RFC 1459 specials). That is enough here because both the names
 * and the rosters are ASCII words separated by spaces and CR, and a narrower
 * predicate can only fail to find a name that contains none of these three --
 * which is not a nickname this test can produce. */
static size_t roster_count(const char *hay, const char *nick)
{
    size_t nlen = strlen(nick);
    size_t found = 0u;

    for (const char *at = hay; (at = strstr(at, nick)) != NULL; at += nlen) {
        char before = (at == hay) ? ' ' : at[-1];
        char after = at[nlen];

        if (!((before >= 'a' && before <= 'z') || (before >= 'A' && before <= 'Z') ||
              (before >= '0' && before <= '9') || before == '_')) {
            if (!((after >= 'a' && after <= 'z') || (after >= 'A' && after <= 'Z') ||
                  (after >= '0' && after <= '9') || after == '_')) {
                found++;
            }
        }
    }
    return found;
}

/* ---------------------------------------------------------------------------
 * THE CASE
 * ---------------------------------------------------------------------------
 * irc.b DIALS irc.z, so there is one link in one direction of configuration and
 * both directions of traffic over the single socket. The beats, in order:
 *
 *   1. B's user claims the name. B's registry is EMPTY about it -- A has no such
 *      user yet -- so the claim succeeds and the name is legitimate. This is the
 *      setup that makes the later duplicate a genuine one rather than a bug.
 *   2. A's user claims the SAME name, and succeeds too, because server_t::nicks is
 *      per-SERVER: a remote `zed` is not in it. This is the divergence 2.1 names.
 *   3. B's SJOIN reaches A, A's registry learns that irc.b holds `zed`, A compares
 *      (irc.z, irc.b), LOSES, and renames its own user. A is the node that has to
 *      notice, and it notices from a peer's report rather than at claim time.
 *   4. The five effects, each from its own direction.
 *   5. The routing, including the two negative cases: a name nobody holds, and a
 *      name held by a server OTHER than the one the client named.
 */
static void case_the_loser_renames_and_the_winner_keeps(void)
{
    nf_node_t z;
    nf_node_t b;
    nf_node_t c;
    test_client_t b_zed;
    test_client_t z_zed;
    test_client_t watch;
    test_client_t router;
    test_client_t roster_after;
    size_t mark;
    char line[160];

    memset(&g_cfg, 0, sizeof g_cfg);
    TF_CHECK_MSG(nf_spawn_inline_named(&z, NAME_Z, child_setup) == 0,
                 "could not spawn node " NAME_Z);
    TF_CHECK_MSG(z.port > 0, "node " NAME_Z " reported no port");

    g_cfg.peer_name = NAME_Z;
    g_cfg.peer_port = z.port;
    TF_CHECK_MSG(nf_spawn_inline_named(&b, NAME_B, child_setup) == 0,
                 "could not spawn node " NAME_B);

    /* The third node dials " NAME_Z " too, and ONE direction per pair is the
     * rule federation/link.h states: a node that configured both ends of a pair
     * both dials and neither accepts. So B and C each configure only Z, and Z
     * configures neither. */
    g_cfg.peer_name = NAME_Z;
    g_cfg.peer_port = z.port;
    TF_CHECK_MSG(nf_spawn_inline_named(&c, NAME_C, child_setup) == 0,
                 "could not spawn node " NAME_C);

    TF_CHECK_MSG(nf_expect(&b, "link_established: peer=" NAME_Z, T_IO_MS) == 0,
                 "node " NAME_B " never established its link to " NAME_Z ": %s",
                 b.out);
    TF_CHECK_MSG(nf_expect(&z, "link_established: peer=" NAME_B, T_IO_MS) == 0,
                 "node " NAME_Z " never accepted the link from " NAME_B ": %s",
                 z.out);
    TF_CHECK_MSG(nf_expect(&c, "link_established: peer=" NAME_Z, T_IO_MS) == 0,
                 "node " NAME_C " never established its link to " NAME_Z ": %s",
                 c.out);
    TF_CHECK_MSG(nf_expect(&z, "link_established: peer=" NAME_C, T_IO_MS) == 0,
                 "node " NAME_Z " never accepted the link from " NAME_C ": %s",
                 z.out);
    /* AND THE RESYNC RAN, so both nodes are past the establishment burst. That
     * matters for the order of the next two beats: a user who connected BEFORE the
     * burst would be in it, and the case below is about a user who connected after
     * it, which is the live path. */
    TF_CHECK_MSG(nf_expect(&z, "fed_burst_applied: peer=" NAME_B, T_IO_MS) == 0,
                 "node " NAME_Z " never applied " NAME_B "'s burst: %s", z.out);

    /* --- beat 1: the LOSER'S user, FIRST and in a channel ------------------ */
    /* irc.z's user claims the name and JOINS before irc.b has anyone called it.
     * That order is the whole of what makes effect 4 testable: a user renamed at
     * the moment it claims a name has not been in a channel yet, so nothing on the
     * far side could hold a roster entry for it and chan_remote_rename() would
     * have nothing to rekey. irc.b's user has to arrive while irc.z's is already
     * a member. */
    register_client(&z_zed, z.port, NICK_Z, "reg-z");
    TF_CHECK_MSG(tc_send(&z_zed, "JOIN " CHAN) == 0, "irc.z's JOIN failed");
    TF_CHECK_MSG(tc_expect(&z_zed, " 366 ", T_IO_MS) == 0,
                 "irc.z's JOIN of " CHAN " never completed");
    TF_CHECK_MSG(nf_expect(&b, "fed_sjoin: channel=" CHAN " member=" NICK_Z,
                           T_IO_MS) == 0,
                 "node " NAME_B " never learned that " NICK_Z " joined " CHAN
                 ", so nothing on it could hold a roster entry to rekey: %s",
                 b.out);
    /* AND irc.z's registry is still EMPTY about this name, which is the state that
     * makes the duplicate later a genuine one: irc.z holds " NICK_Z " and has been
     * told nothing about irc.b. */
    TF_CHECK_MSG(nf_expect_u64(&z, "nickreg_known=", 0u, T_IO_MS) == 0,
                 "node " NAME_Z " already has a remote-nick entry before any peer "
                 "has reported one, so the case is measuring a table that was not "
                 "built by the events below: %s",
                 z.out);

    /* The second member on irc.z, whose only job in this file is to be a client
     * that shares a channel with the renamed user and did not ask for the change. */
    register_client(&watch, z.port, NICK_W, "reg-watch");
    TF_CHECK_MSG(tc_send(&watch, "JOIN " CHAN) == 0, "the watcher's JOIN failed");
    TF_CHECK_MSG(tc_expect(&watch, " 366 ", T_IO_MS) == 0,
                 "the watcher's JOIN never completed");

    /* --- beat 2: the WINNER'S user claims the same name -------------------- */
    /* IT IS A REAL DUPLICATE NOW: irc.z holds " NICK_Z " in a channel and knows
     * nothing, and irc.b's client is about to take the same name. irc.b's claim
     * SUCCEEDS, and the reason it does is worth stating because it is the whole of
     * 2.1's problem: server_t::nicks is per-SERVER, so a remote name is not in it
     * and the lookup-and-insert has nothing to collide with. A node that resolved
     * duplicates at claim time against its LOCAL table would find nothing here too,
     * which is why this is not the interesting moment for the rename. */
    register_client(&b_zed, b.port, NICK_B, "reg-b");
    /* AND irc.b, WHICH DOES KNOW, KEEPS THE NAME. 'b' < 'z', so irc.b is the
     * smaller name and 2.1's order leaves the nick to it. This is asserted HERE,
     * at the moment the claim is made, because it is the claim that must NOT
     * rename: a test that only checked the winner's silence after the loser had
     * already renamed would pass against a node that renamed both users. */
    TF_CHECK_MSG(nf_expect(&b, "nick_duplicate: nick=" NICK_B " local=" NAME_B
                              " remote=" NAME_Z " verdict=LOCAL_WINS",
                           T_IO_MS) == 0,
                 "node " NAME_B " did not record that it holds " NICK_B " while "
                 "peer " NAME_Z " holds it too. 'b' < 'z', so " NAME_B " is the "
                 "smaller name and is the one 2.1's order says keeps the nick: "
                 "%s",
                 b.out);
    /* AND irc.b's client is NOT told anything, on the wire. This is a 400 ms
     * absence rather than a sleep, and it is checked twice -- once here for the
     * claim, once after the loser's rename for the whole node -- because the two
     * are different failures: a rename at claim time is a policy that picked the
     * wrong node, and a rename later is a policy that ran twice. */
    mark = tc_received(&b_zed);
    (void)snprintf(line, sizeof line, "PING :after-claim");
    TF_CHECK_MSG(tc_send(&b_zed, line) == 0, "irc.b's user's PING send failed");
    TF_CHECK_MSG(tc_expect(&b_zed, "after-claim", T_IO_MS) == 0,
                 "irc.b's user never got its PONG: %s", tc_buffer(&b_zed));
    TF_CHECK_MSG(strstr(since(&b_zed, mark), " NICK ") == NULL,
                 "irc.b renamed the user that 2.1's order says it keeps, so the "
                 "duplicate is being resolved by renaming BOTH of them: %s",
                 since(&b_zed, mark));
    TF_CHECK_MSG(strstr(since(&b_zed, mark), " 433 ") == NULL,
                 "irc.b answered 433 for a name 2.1's policy says it may hold: %s",
                 since(&b_zed, mark));

    /* --- beat 3: the loser is told by a PEER'S REPORT, and acts ------------ */
    /* irc.b's user JOINS, which is the only thing that reports the claim to
     * irc.z. No wait before it: the point of this beat is that irc.z finds out on
     * its own, and a case that waited for the report before triggering the
     * reaction would be asserting the report rather than the policy. */
    TF_CHECK_MSG(tc_send(&b_zed, "JOIN " CHAN) == 0, "irc.b's JOIN failed");
    TF_CHECK_MSG(tc_expect(&b_zed, " 366 ", T_IO_MS) == 0,
                 "irc.b's JOIN never completed");
    TF_CHECK_MSG(nf_expect(&z, "from=" NICK_Z " to=" NICK_Z
                           "_ reason=REMOTE_HOLDER holder=" NAME_B,
                           T_IO_MS) == 0,
                 "node " NAME_Z " did not rename its own " NICK_Z " when it "
                 "learned that " NAME_B " holds the same name. 'z' > 'b', so "
                 "irc.z is the greater name and is the one 2.1's policy renames: "
                 "%s",
                 z.out);
    /* AND THE FD IS NOT IN THE NEEDLE, deliberately: the rename is identified by
     * its name pair, its reason and its holder, and pinning the descriptor would
     * make the assertion about the ORDER in which the case opened its sockets --
     * a fact about the test rather than about the policy. */
    TF_CHECK_MSG(nf_expect_u64(&z, "nickreg_known=", 1u, T_IO_MS) == 0,
                 "node " NAME_Z "'s registry did not grow, so the rename it just "
                 "performed cannot have come from a peer report: %s",
                 z.out);

    /* --- beat 4: the five effects ------------------------------------------ */

    /* 2. THE CLIENT. The renamed user is told, on the wire, and is NOT told 433:
     * a 433 here would be a client retrying a name the mesh has already resolved,
     * and a client that did that would end up with a second divergence. The buffer
     * is read from the registration drain, so the assertion is about what came
     * AFTER the rename and not about the 001. */
    mark = tc_received(&z_zed);
    (void)snprintf(line, sizeof line, "PING :after-rename");
    TF_CHECK_MSG(tc_send(&z_zed, line) == 0, "the post-rename PING send failed");
    TF_CHECK_MSG(tc_expect(&z_zed, "after-rename", T_IO_MS) == 0,
                 "the renamed client never got its PONG, so the node did not "
                 "process the rename before answering: %s",
                 tc_buffer(&z_zed));
    TF_CHECK_MSG(strstr(since(&z_zed, mark), " 433 ") == NULL,
                 "the renamed client was answered 433 as well as being renamed, "
                 "so a client would retry a name the mesh has already resolved: "
                 "%s",
                 since(&z_zed, mark));
    TF_CHECK_MSG(strstr(since(&z_zed, mark), " NICK ") != NULL,
                 "the renamed user was never told on the wire, so its own display "
                 "still shows a name the server no longer holds: %s",
                 since(&z_zed, mark));

    /* 3. THE LOCAL CHANNELS. The watcher shares a channel with the renamed user,
     * and a rename no other member can see is the divergence 2.1's policy is about
     * one layer down. */
    mark = tc_received(&watch);
    (void)snprintf(line, sizeof line, "PING :after-watch");
    TF_CHECK_MSG(tc_send(&watch, line) == 0, "the watcher's PING send failed");
    TF_CHECK_MSG(tc_expect(&watch, "after-watch", T_IO_MS) == 0,
                 "the watcher never got its PONG, so node " NAME_Z " had not "
                 "finished the rename when this assertion ran: %s",
                 tc_buffer(&watch));
    TF_CHECK_MSG(strstr(since(&watch, mark), " NICK ") != NULL,
                 "a client sharing " CHAN " with the renamed user was never told, "
                 "so two clients in one channel show two names for one user: %s",
                 since(&watch, mark));

    /* 4. THE MESH. irc.b rekeys what it learned, and the observable proves the
     * registry AND the roster moved: `rosters=` is the number of channel rosters
     * that held the old name. A node that applied the rename to its registry alone
     * would resolve `zed@irc.z` correctly and would still show a client a roster
     * naming a user who no longer exists. */
    TF_CHECK_MSG(nf_expect(&b,
                           "fed_snick: server=" NAME_Z " from=" NICK_Z " to=" NICK_Z
                           "_ rosters=1",
                           T_IO_MS) == 0,
                 "node " NAME_B " did not apply the rename that node " NAME_Z
                 " performed. rosters=1 is the assertion that distinguishes a "
                 "rekeyed registry from a rekeyed roster: %s",
                 b.out);

    /* 5. THE WINNER KEEPS IT, which is the convergence claim. 'z' > 'b' makes
     * irc.b the smaller name and the keeper, and if irc.b also renamed then two
     * nodes would have given way and the mesh would have resolved the duplicate by
     * creating a second one. It is asserted by the absence of a rename line on
     * irc.b, which is why the wait above has to have been for irc.b's OWN rename
     * rather than a shared one. */
    /* AND ITS CLIENT SAYS NOTHING, which is the same claim on the wire rather than
     * in a log line, and is checked twice for two different failures: a rename at
     * claim time is a policy that picked the wrong node, and a rename after the
     * loser's is a policy that ran twice. The earlier check is in beat 2; this one
     * is after the whole mesh has converged.
     *
     * IT IS NOT A WAIT FOR AN ABSENCE ON THE NODE'S OWN OUTPUT, which would need a
     * timeout and would dump the child on the way out: the claim "this client was
     * not sent a NICK" is exactly a statement about this client's buffer, and the
     * buffer is complete as soon as the node has answered the PING that follows. */
    mark = tc_received(&b_zed);
    (void)snprintf(line, sizeof line, "PING :after-win");
    TF_CHECK_MSG(tc_send(&b_zed, line) == 0, "irc.b's user's PING send failed");
    TF_CHECK_MSG(tc_expect(&b_zed, "after-win", T_IO_MS) == 0,
                 "irc.b's user never got its PONG: %s", tc_buffer(&b_zed));
    TF_CHECK_MSG(strstr(since(&b_zed, mark), " NICK ") == NULL,
                 "irc.b renamed the user that 2.1's order says it keeps, so both "
                 "servers gave way: %s",
                 since(&b_zed, mark));

    /* --- beat 5: the ROUTING, and its two negative cases -------------------- */
    /* 2.1's scoped identity is `nick@server`, and 3.1's `message` row for it has
     * always read "forward to that server". Nothing could forward it before this
     * pass: fanout_resolve() recognised the shape and produced a target with no
     * destination, and msg_verbs.c answered 401 for the row unconditionally. The
     * registry is what makes the answer computable -- it says WHICH server holds
     * the name, and the link table says whether that server can be reached.
     *
     * NOTE THE DIRECTION. The routing is asserted FROM irc.z TO irc.b, not from
     * irc.b to irc.b: the registry holds only REMOTE nicks, because a local name is
     * server_t::nicks' business and 2.1's "bob@a and bob@b are distinct registry
     * keys" is a statement about names on different servers. A client on irc.b
     * writing `zed@irc.b` is naming a user of its own node through a qualified
     * form, and the honest answer to that is 401 rather than a self-forward --
     * which is the wrong-scope case below, stated in the direction that reaches
     * it. */

    /* A. A SCOPED NAME THIS NODE CAN ROUTE. `zed@irc.b` is irc.b's user, which
     * irc.z learned from an SJOIN, and the assertion is on the FAR SIDE: irc.b's own
     * user receives the text. "Not refused" would be a much weaker claim, and 401
     * is exactly what a node whose registry was empty would have answered -- which
     * is what msg_verbs.c used to answer always. */
    (void)snprintf(line, sizeof line, "PRIVMSG " NICK_B "@" NAME_B
                                      " :route-payload");
    TF_CHECK_MSG(tc_send(&watch, line) == 0, "the scoped PRIVMSG send failed");
    TF_CHECK_MSG(tc_expect(&b_zed, "route-payload", T_IO_MS) == 0,
                 "a `nick@server` target was not delivered to the server that "
                 "holds the nick. 3.1's row for it has always been 'forward to "
                 "that server', and 2.1's registry is what makes it computable: "
                 "%s",
                 tc_buffer(&b_zed));

    /* B. THE RENAMED NAME, SCOPED TO ITS NEW HOLDER. The other direction, and the
     * assertion that fails if the rename never reached the far side's registry:
     * irc.b holds `zed_` because of the SNICK, so `zed_@irc.z` resolves ON irc.b and
     * the text lands on irc.z's renamed user. A node that applied the rename to its
     * channel rosters but not to its registry would 401 here. */
    register_client(&router, b.port, NICK_R, "reg-router");
    (void)snprintf(line, sizeof line, "PRIVMSG " NICK_Z "_@" NAME_Z
                                      " :renamed-payload");
    TF_CHECK_MSG(tc_send(&router, line) == 0,
                 "the renamed-scope PRIVMSG send failed");
    TF_CHECK_MSG(tc_expect(&z_zed, "renamed-payload", T_IO_MS) == 0,
                 "a `nick@server` for the user a rename created was not delivered. "
                 "The rename reached irc.b's registry (fed_snick above), so this is "
                 "about the ROUTING and not about the rename: %s",
                 tc_buffer(&z_zed));

    /* C. THE SCOPE NAMES A SERVER THAT DOES NOT HOLD THE NAME. Two of these, and
     * they are the two directions of the same refusal.
     *
     * C1 is a SELF-scope: `zed_@irc.b`, sent from irc.b. irc.b does not hold
     * `zed_` -- the name was created on irc.z by the rename -- and the scope names
     * this node, so there is nothing to forward to and nothing to resolve locally.
     * This case is also the one that proves the self-scope rule above is not a
     * blanket "always deliver": a node that resolved any `nick@<own name>` to a
     * local user without checking would 401 nothing and would deliver a message to
     * the wrong person. */
    (void)snprintf(line, sizeof line, "PING :scope-a");
    TF_CHECK_MSG(tc_send(&router, line) == 0, "a PING send failed");
    TF_CHECK_MSG(tc_expect(&router, "scope-a", T_IO_MS) == 0,
                 "the router never got its PONG, so the answers below would be "
                 "about bytes read earlier: %s",
                 tc_buffer(&router));
    mark = tc_received(&router);
    (void)snprintf(line, sizeof line, "PRIVMSG " NICK_Z "_@" NAME_B " :self-scope");
    TF_CHECK_MSG(tc_send(&router, line) == 0, "the self-scope send failed");
    (void)snprintf(line, sizeof line, "PING :scope-b");
    TF_CHECK_MSG(tc_send(&router, line) == 0, "the second PING send failed");
    TF_CHECK_MSG(tc_expect(&router, "scope-b", T_IO_MS) == 0,
                 "the router never got its second PONG: %s", tc_buffer(&router));
    TF_CHECK_MSG(strstr(since(&router, mark), " 401 ") != NULL,
                 "a self-scoped `nick@server` for a name THIS node does not hold "
                 "was not answered 401, so a qualified name reached a delivery "
                 "path for a user who does not exist here: %s",
                 since(&router, mark));

    /* C2 is a REMOTE scope naming the WRONG server: `zed@irc.c`, sent from
     * irc.z. irc.z's registry says irc.b holds `zed`, and irc.c holds nothing --
     * it is not even a configured peer. The scope is the client's claim about WHERE
     * the user is, and the registry is this node's claim; when they disagree the
     * client is wrong, and 2.1's scoped identity is a request for one SPECIFIC
     * holder rather than a question about the name.
     *
     * THIS IS THE CASE THAT DISTINGUISHES RESOLVE FROM REDIRECT, and it is the one
     * the teeth check targets. A resolver that ignored the scope and asked only
     * "who holds zed?" would forward to irc.b and the message would arrive -- so
     * "was it delivered?" is NOT the assertion here. The assertion is 401, and the
     * reason is that a client which asked for irc.c must not be given irc.b's user
     * as though it had asked for it. There is no way to tell the two apart at the
     * far end, so the only honest place to make the distinction is here. */
    mark = tc_received(&watch);
    (void)snprintf(line, sizeof line, "PRIVMSG " NICK_B "@irc.c :wrong-scope");
    TF_CHECK_MSG(tc_send(&watch, line) == 0, "the wrong-scope send failed");
    (void)snprintf(line, sizeof line, "PING :scope-c");
    TF_CHECK_MSG(tc_send(&watch, line) == 0, "the third PING send failed");
    TF_CHECK_MSG(tc_expect(&watch, "scope-c", T_IO_MS) == 0,
                 "the watcher never got its PONG: %s", tc_buffer(&watch));
    TF_CHECK_MSG(strstr(since(&watch, mark), " 401 ") != NULL,
                 "a `nick@server` naming a server that does NOT hold that nick was "
                 "not answered 401. Redirecting to the holder instead would give a "
                 "client a different server than the one it named, and the client "
                 "cannot tell at the far end which one it got: %s",
                 since(&watch, mark));

    /* C3 is the refusal a two-node mesh cannot produce, and it is the reason this
     * case has a third node. A client on " NAME_Z " writes `zed@irc.c`: irc.c IS a
     * peer this node can reach, and irc.c does NOT hold `zed` -- irc.b does.
     *
     * TWO CHECKS COULD ANSWER IT AND ONLY ONE IS RIGHT. The reachability check
     * ("is the named server a peer I can route to?") says yes and forwards, and the
     * message arrives at irc.c, which 401s it into a federation guard because
     * irc.c has never heard of the nick -- so the sender is told NOTHING and cannot
     * tell a mistyped scope from a dropped message. The scope check ("does the
     * registry agree the NAMED server is the holder?") says no, and the sender gets
     * a 401 it can act on.
     *
     * IN A TWO-NODE MESH THESE ARE THE SAME STRING, which is why this case cannot
     * exist there: with one peer, "the server you named is not the holder" and "the
     * server you named is not a peer I can reach" name the same server. A
     * two-node test would pass against a resolver that had only the reachability
     * check, and would report that it had proved the scope is honoured. */
    mark = tc_received(&watch);
    (void)snprintf(line, sizeof line, "PRIVMSG " NICK_B "@" NAME_C " :wrong-peer");
    TF_CHECK_MSG(tc_send(&watch, line) == 0, "the wrong-peer send failed");
    (void)snprintf(line, sizeof line, "PING :scope-c2");
    TF_CHECK_MSG(tc_send(&watch, line) == 0, "the wrong-peer PING send failed");
    TF_CHECK_MSG(tc_expect(&watch, "scope-c2", T_IO_MS) == 0,
                 "the watcher never got its PONG: %s", tc_buffer(&watch));
    TF_CHECK_MSG(strstr(since(&watch, mark), " 401 ") != NULL,
                 "a `nick@server` naming a REACHABLE peer that does not hold that "
                 "nick was not answered 401. The reachability check alone would "
                 "have forwarded it, and the far side would have dropped it into a "
                 "federation guard, so the client would have been told nothing: "
                 "%s",
                 since(&watch, mark));

    /* D. A NAME NOBODY HOLDS. 401 for the OTHER reason, and 401 for both: 4.4 has
     * no numeric for "the user exists and this node cannot reach them", and 401 is
     * the answer a client already knows how to handle. The 401s above and here are
     * deliberately the same number for two different reasons -- a client can only
     * act on the number, and inventing a second one for "unreachable" would be a
     * numeric every client would have to be taught. */
    mark = tc_received(&router);
    (void)snprintf(line, sizeof line, "PRIVMSG nobody@" NAME_Z " :gone");
    TF_CHECK_MSG(tc_send(&router, line) == 0, "the unknown-nick send failed");
    (void)snprintf(line, sizeof line, "PING :scope-d");
    TF_CHECK_MSG(tc_send(&router, line) == 0, "the fourth PING send failed");
    TF_CHECK_MSG(tc_expect(&router, "scope-d", T_IO_MS) == 0,
                 "the router never got its fourth PONG: %s", tc_buffer(&router));
    TF_CHECK_MSG(strstr(since(&router, mark), " 401 ") != NULL,
                 "a `nick@server` for a nick no server holds was not answered 401: "
                 "%s",
                 since(&router, mark));

    /* E. AND THE SELF-SCOPE THAT WORKS, which is the half of the rule C1 could
     * have broken. irc.b's own user writing `zed@irc.b` -- its own name, on its
     * own node, through the qualified form -- is delivered, because 2.1's scoped
     * identity does not require the server to be a different one and a node that
     * 401'd it would be denying a client a user it is looking at. */
    (void)snprintf(line, sizeof line, "PING :scope-e");
    TF_CHECK_MSG(tc_send(&router, line) == 0, "the fifth PING send failed");
    TF_CHECK_MSG(tc_expect(&router, "scope-e", T_IO_MS) == 0,
                 "the router never got its fifth PONG: %s", tc_buffer(&router));
    mark = tc_received(&router);
    (void)snprintf(line, sizeof line, "PRIVMSG " NICK_B "@" NAME_B " :self-ok");
    TF_CHECK_MSG(tc_send(&router, line) == 0, "the self-scope send failed");
    TF_CHECK_MSG(tc_expect(&b_zed, "self-ok", T_IO_MS) == 0,
                 "a self-scoped `nick@server` naming a user THIS node holds was "
                 "not delivered. 2.1's scoped identity does not require the server "
                 "to be a different one, and 401 here would deny a client a user "
                 "standing next to it: %s",
                 tc_buffer(&b_zed));
    TF_CHECK_MSG(strstr(since(&router, mark), " 401 ") == NULL,
                 "a self-scoped name this node holds was answered 401 as well as "
                 "being delivered: %s",
                 since(&router, mark));

    /* --- and the rosters agree with all of it ------------------------------ */
    /* ONE FINAL ROSTER, from a client that has never asked anything, so the
     * assertion cannot be satisfied by a 353 this same connection received
     * earlier. Both names are present on irc.z's channel -- `zed` as a REMOTE
     * member (irc.b's user, which kept the name) and `zed_` as irc.z's own renamed
     * user -- and `zed` appears exactly once, which is the claim a merge-then-rename
     * would break. */
    mark = ask_names(&roster_after, z.port, "roster", "roster-after");
    TF_CHECK_MSG(strstr(since(&roster_after, mark), NICK_B) != NULL,
                 "irc.b's user is not in " CHAN "'s roster on node " NAME_Z
                 " after the rename, so the winner was renamed as well: %s",
                 since(&roster_after, mark));
    TF_CHECK_MSG(strstr(since(&roster_after, mark), NICK_Z "_") != NULL,
                 "the renamed user is not in " CHAN "'s roster on node " NAME_Z
                 ", so irc.z renamed its registry without telling its own "
                 "channel: %s",
                 since(&roster_after, mark));
    TF_CHECK_MSG(roster_count(since(&roster_after, mark), NICK_B) == 1u,
                 NICK_B " appears %zu times in " CHAN "'s roster on node " NAME_Z
                 ", so the rename created a second entry for one user: %s",
                 roster_count(since(&roster_after, mark), NICK_B),
                 since(&roster_after, mark));
    TF_CHECK_MSG(roster_count(since(&roster_after, mark), NICK_Z "_") == 1u,
                 NICK_Z "_ appears %zu times in " CHAN "'s roster on node " NAME_Z
                 ", so the renamed user is a member of a channel the policy does "
                 "not know about: %s",
                 roster_count(since(&roster_after, mark), NICK_Z "_"),
                 since(&roster_after, mark));

    TF_CHECK_MSG(nf_stop(&z) == 0, "node " NAME_Z " did not exit cleanly");
    TF_CHECK_MSG(nf_stop(&b) == 0, "node " NAME_B " did not exit cleanly");
    TF_CHECK_MSG(nf_stop(&c) == 0, "node " NAME_C " did not exit cleanly");
    tc_close(&b_zed);
    tc_close(&z_zed);
    tc_close(&watch);
    tc_close(&router);
    tc_close(&roster_after);
    nf_free(&z);
    nf_free(&b);
    nf_free(&c);
}

int main(void)
{
    case_the_loser_renames_and_the_winner_keeps();
    tf_done("nick_duplicate");
    return 0;
}
