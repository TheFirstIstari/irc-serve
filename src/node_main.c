/* node_main.c -- the node binary: bring the listener up and drive the loop.
 *
 * Phase 2 is the first phase in which this executable does something real.
 * Before it opened a socket, accepted one connection, printed the peer address
 * and closed it immediately; that is gone. The loop in core/poll_loop.c now
 * owns the node's lifetime: it accepts, frames, parses, drains write queues and
 * reaps.
 *
 * ---------------------------------------------------------------------------
 * THE PORT IS AN ARGUMENT, AND 0 IS MEANINGFUL
 * ---------------------------------------------------------------------------
 *   irc-serve [port]
 *
 * The port used to be the literal 6667 compiled into main(). It is an argument
 * now, and `port 0` is explicitly supported: the kernel picks an unused
 * ephemeral port, and this executable reports which one via server_port() so a
 * caller can connect to it. That is what lets the integration tests run in
 * parallel without a port table and without a retry loop.
 *
 * ---------------------------------------------------------------------------
 * AND NOW THE OPTIONS, WHICH MUST NOT BREAK THAT
 * ---------------------------------------------------------------------------
 *   --name NAME            --secret S            --peer NAME,HOST,PORT
 *
 * `irc-serve 6667` behaves EXACTLY as it did before this phase: same default
 * name, same default port, same default (empty) secret, same stdout. The bare
 * port argument is still accepted, in any position, and it is still the only
 * positional argument -- a second one is an error rather than an ignored word,
 * because silently dropping a second port would be a node listening somewhere
 * other than the operator asked for.
 *
 * ONE QUALIFICATION on "behaves exactly as it did", and it is about the empty
 * secret rather than about the command line: the default secret is still "", but
 * it now means this node ACCEPTS NO INBOUND PEER rather than this node's peers
 * are unauthenticated. A node with no --secret serves clients exactly as before
 * and refuses every inbound FEDERATE. The startup line is unchanged in shape
 * (`secret=none`), --help says what `none` means, and
 * NODE_DEFAULT_SECRET below carries the argument.
 *
 * ---------------------------------------------------------------------------
 * PEER ADDRESSES ARE RESOLVED HERE, IN main(), BEFORE THE LOOP
 * ---------------------------------------------------------------------------
 * 3.4: "Any getaddrinfo in the loop stalls every client on the node", and
 * core/server.h is explicit that server_dial() must take a struct sockaddr so
 * that no resolution helper can be added next to it later. So the only
 * getaddrinfo in this tree is resolve_peer() below, it is called from main()
 * before the loop is armed, and the address it produces is handed to
 * fed_link_configure() as a struct sockaddr. The resolution is a STEP here
 * rather than something a loop could do, and that is the whole reason the
 * --peer argument is NAME,HOST,PORT rather than something this file is
 * tempted to re-resolve later.
 *
 * The first result is taken and the rest are freed: a peer address is a
 * configured address, and a host with several A records is a configuration
 * question (which one? round-robin?) rather than something to answer silently
 * by taking the first. The alternative -- collecting them all -- is Phase 9's
 * peer-discovery problem, and doing half of it here would be worse than not
 * doing it.
 *
 * ---------------------------------------------------------------------------
 * [observable] OUTPUT IS PART OF THE CONTRACT
 * ---------------------------------------------------------------------------
 * The lines below are how the node reports what it did, and the integration
 * tests parse them. Two properties matter and both are deliberate:
 *
 *   - stdout is set LINE BUFFERED before anything is printed. The default is
 *     full buffering when stdout is a pipe, which would leave a parent reading
 *     this output blocked until the process exits -- and this process is
 *     supposed to keep running.
 *   - the readiness line is emitted only once poll() is about to be armed, so a
 *     caller that waits for it is waiting for a node that is actually serving.
 *     6.2 requires the same handshake for the two-node fixture, where each
 *     child writes one line once its loop is armed; this is that line.
 *
 * ---------------------------------------------------------------------------
 * WHAT THE NODE ANSWERS
 * ---------------------------------------------------------------------------
 * Phase 3: the client command surface, installed as srv.dispatch just below.
 * PASS, NICK, USER, MOTD, PING, PONG and QUIT, the 001-005 welcome burst, and
 * 451/421 for everything else. The numerics are built and queued in
 * core/reply.c and nowhere else, which is what keeps them off a peer link
 * (3). Phase 6 adds the peer link -- the FEDERATE exchange and the tick that
 * keeps it alive -- and the node still answers 421 for client verbs it does
 * not have.
 */
#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "core/commands.h"
#include "core/poll_loop.h"
#include "core/server.h"
#include "federation/link.h"

/* The node's own name, when --name is not given. It must satisfy the 2.4 tag
 * grammar, because it is stamped on every outbound irc-serve-origin tag, and a
 * name that cannot be stamped would break the never-forward-own-origin rule at
 * the first relay. It is also the prefix on every numeric (002, 004, 005's
 * context, PONG) and the <target>'s server half. */
#define NODE_NAME "irc.test"

/* The secret when --secret is not given. EMPTY, and that is a real default
 * rather than a placeholder, but what it MEANS changed when the inbound
 * handshake was given a policy.
 *
 * It used to mean "peers are unauthenticated": the secret step compared the
 * offered value against "", and two empty strings compared equal, so on a node
 * with no --secret the secret step could not be failed at all. (How far that
 * reached is worth stating precisely, because it was less than it looks: an
 * empty parameter cannot be put on the wire in a non-final position by this
 * node's parser, so a peer could not actually offer one, and the thing standing
 * between a default-configured node and a stranger was a parser rule rather than
 * a check. Step 2 of fed_check_federate() in federation/link.c says so in full.
 * What is not in dispute is that the startup line said only `secret=none`,
 * which reads like a missing feature rather than a missing credential.)
 *
 * It means now that this node federates with NOBODY. `irc-serve 6667` with no
 * --secret starts, binds, serves clients and prints the same lines it always
 * has -- the client surface is entirely untouched -- and it REFUSES every
 * inbound FEDERATE with its own reason, NO_SECRET, so an operator reading
 * `reason=` can tell "somebody guessed wrong" (BAD_SECRET, a credential under
 * attack) from "this node is not configured to federate" (a missing --secret).
 * Federation is opt-in here: a node federates because it was given a secret.
 *
 * The cost, for anyone who was relying on the old reading: smaller than it first
 * looks, because a node with no --secret could not federate in either direction
 * before this. Dialling one put a FEDERATE with an empty secret parameter on the
 * wire, and message_format() refuses a parameter the wire cannot represent in a
 * non-final position, so the node reported `link_send_failed:
 * reason=UNRENDERABLE` and sent nothing. There is therefore no working
 * all-`--secret`-less mesh for this to break; what changes is that the refusal
 * is now this node's own decision rather than an accident of a parser rule, that
 * it is named NO_SECRET instead of being folded into BAD_SECRET, and that it
 * covers the INBOUND side too. The peer handshake did not exist before Phase 6,
 * so no deployment can have depended on it, and the alternative was shipping a
 * mesh that authenticates nobody by default. See fed_check_federate() in
 * federation/link.c for the argument at the place it is enforced. */
#define NODE_DEFAULT_SECRET ""

#define NODE_DEFAULT_PORT 6667

/* How many --peer options are accepted, and why the limit is here rather than
 * only in the table.
 *
 * IRC_FED_MAX_PEERS is core/server.h's INITIAL CAPACITY of the link vector, and
 * the vector grows past it, so it is not a limit on how many peers a node can
 * be linked to. The limit that belongs to this file is the size of a command
 * line, and the number is IRC_FED_MAX_PEERS because a mesh of this design's
 * size is a handful of nodes and a command line with seventeen peers in it is
 * a configuration file that should have been one. The two being different is
 * recorded rather than hidden: the cap here is a CLI-surface decision, the
 * growth in fed_link_configure() is a table decision, and neither one enforces
 * the other. */
#define NODE_MAX_PEERS IRC_FED_MAX_PEERS

/* SIGTERM and SIGINT stop the loop; SIGUSR1 exists so the EINTR path is
 * reachable from outside. Neither sets SA_RESTART: the handlers must interrupt
 * poll() rather than have it silently restarted, because an EINTR that the
 * loop does not observe is an EINTR path that is never tested. */
static void on_stop_signal(int sig)
{
    (void)sig;
    poll_loop_request_stop();
}

static void on_usr1_signal(int sig)
{
    (void)sig;
    /* Deliberately empty. The point is that the signal interrupts poll() and
     * the loop survives it; the handler must not request a stop. */
}

static int install_handler(int sig, void (*handler)(int))
{
    struct sigaction sa;

    memset(&sa, 0, sizeof sa);
    sa.sa_handler = handler;
    /* sigemptyset() cannot fail: POSIX specifies it as always returning 0, and
     * the whole mask is already zero from the memset above. Its return value is
     * deliberately not checked, because a branch on it would be dead code. */
    (void)sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0; /* no SA_RESTART: poll() must return EINTR */
    return sigaction(sig, &sa, NULL);
}

static void usage(FILE *out, const char *argv0)
{
    fprintf(out, "usage: %s [port] [--name NAME] [--secret S]\n", argv0);
    fprintf(out, "            [--peer NAME,HOST,PORT]...\n");
    fprintf(out, "\n");
    fprintf(out, "  port   TCP port to listen on, 0-%d; 0 asks the kernel for\n"
                 "         an ephemeral port and reports which one it chose\n",
            65535);
    fprintf(out, "\n");
    fprintf(out, "  --name NAME\n"
                 "         this node's server name (2.4 tag grammar: letters,\n"
                 "         digits, '-' and '.'; must start with a letter or\n"
                 "         digit). Default: %s\n", NODE_NAME);
    fprintf(out, "\n");
    fprintf(out, "  --secret S\n"
                 "         the shared federation secret a peer must present in\n"
                 "         FEDERATE. Default: empty, which means this node\n"
                 "         REFUSES inbound peers -- it federates with nobody,\n"
                 "         and a claim is rejected as reason=NO_SECRET rather\n"
                 "         than as a wrong secret. Set one to federate at all.\n"
                 "         At most %d bytes.\n",
            IRC_FED_MAX_SECRET - 1);
    fprintf(out, "\n");
    fprintf(out, "  --peer NAME,HOST,PORT\n"
                 "         a peer to link with, repeatable up to %d. NAME is the\n"
                 "         peer's server name and must satisfy the same grammar\n"
                 "         as --name; HOST and PORT are resolved to an address\n"
                 "         ONCE, at startup, and never inside the event loop.\n",
            NODE_MAX_PEERS);
    fprintf(out, "\n");
    fprintf(out, "  --help  print this text and exit\n");
    fprintf(out, "\n");
    fprintf(out, "A link exists once a peer is configured and establishes when\n"
                 "EITHER side connects, so two nodes that both list each other\n"
                 "as a peer will both dial and neither will accept. Configure\n"
                 "each pair in ONE direction.\n");
}

/* Parse the port argument. Returns 0 on success, -1 if it is not a number in
 * range, and 1 if no argument was given (which is not an error: the default
 * port applies). */
static int parse_port(const char *arg, int *port)
{
    char *end = NULL;
    long value;

    if (arg == NULL || arg[0] == '\0') {
        return 1;
    }
    errno = 0;
    value = strtol(arg, &end, 10);
    if (errno != 0 || end == arg || *end != '\0' || value < 0 || value > 65535) {
        return -1;
    }
    *port = (int)value;
    return 0;
}

/* One --peer argument, split into its three fields. Kept as a struct because
 * the resolution is a separate step that runs in main(): nothing here touches a
 * socket, and the split is the last thing that happens to the string before
 * main() hands each field to a function that owns it. */
typedef struct {
    char     name[IRC_MAX_SERVER_NAME + 1];
    char     host[256];
    char     port[16];
} node_peer_t;

/* The command line, parsed. Defaults are filled in first so that every field is
 * either a default or something the operator asked for, and there is no state
 * in which a field is "unset" -- which is what makes the backward-compatibility
 * argument checkable: with no arguments at all, this struct is exactly what the
 * node used before this phase had a command line. */
typedef struct {
    const char *name;
    const char *secret;
    int         port;
    int         have_port;
    node_peer_t peers[NODE_MAX_PEERS];
    int         npeers;
} node_opts_t;

static void opts_defaults(node_opts_t *o)
{
    memset(o, 0, sizeof *o);
    o->name = NODE_NAME;
    o->secret = NODE_DEFAULT_SECRET;
    o->port = NODE_DEFAULT_PORT;
}

/* Split `spec` into name, host, port. Returns 0 on success, -1 on a malformed
 * specification.
 *
 * Exactly two commas, and the third field is a decimal port. Deliberately
 * strict: a --peer argument that is nearly right must be refused, because the
 * alternative is a node that resolves a hostname built out of two fields and
 * dials something the operator did not name. The hostname field is bounded at
 * sizeof(host) rather than unbounded, which is what keeps the later
 * getaddrinfo() call inside a buffer it does not have to trust. */
static int parse_peer(const char *spec, node_peer_t *out)
{
    const char *first;
    const char *second;
    size_t n;

    if (spec == NULL || out == NULL) {
        return -1;
    }
    first = strchr(spec, ',');
    if (first == NULL) {
        return -1;
    }
    second = strchr(first + 1, ',');
    if (second == NULL || strchr(second + 1, ',') != NULL) {
        return -1;
    }
    n = (size_t)(first - spec);
    if (n == 0u || n > (size_t)IRC_MAX_SERVER_NAME) {
        return -1;
    }
    memcpy(out->name, spec, n);
    out->name[n] = '\0';
    n = (size_t)(second - (first + 1));
    if (n == 0u || n >= sizeof out->host) {
        return -1;
    }
    memcpy(out->host, first + 1, n);
    out->host[n] = '\0';
    n = strlen(second + 1);
    if (n == 0u || n >= sizeof out->port) {
        return -1;
    }
    memcpy(out->port, second + 1, n + 1u);
    /* The port must be DECIMAL, and this check is here rather than left to
     * getaddrinfo for a reason that is not tidiness: getaddrinfo's second
     * argument is a SERVICE, and a service that is not a number is looked up in
     * the system service database. `--peer a,host,ssh` would then quietly mean
     * port 22 on a node where the operator wrote a word, and the link would be
     * refused much later with a much less obvious reason. */
    {
        size_t i;

        for (i = 0; i < n; i++) {
            if (out->port[i] < '0' || out->port[i] > '9') {
                return -1;
            }
        }
    }
    return 0;
}

/* The command line. Returns 0 on success, -1 on a usage error (already
 * reported on stderr), and 1 when --help was asked for.
 *
 * Options are recognised in any position and the bare port is a positional, so
 * `irc-serve --name irc.a 0` and `irc-serve 0 --name irc.a` are the same
 * command. An argument that begins with '-' and is not a known option is an
 * ERROR rather than an unknown positional: a mistyped flag is a mistake, and
 * treating it as a port is how a node ends up listening on a number nobody
 * typed. */
static int parse_args(int argc, char **argv, node_opts_t *o)
{
    int i;
    int rc;

    opts_defaults(o);
    for (i = 1; i < argc; i++) {
        const char *arg = argv[i];
        const char *value = NULL;

        if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) {
            return 1;
        }
        if (strcmp(arg, "--name") == 0 || strcmp(arg, "--secret") == 0 ||
            strcmp(arg, "--peer") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "irc-serve: %s needs a value\n", arg);
                return -1;
            }
            value = argv[++i];
        } else if (arg[0] == '-') {
            fprintf(stderr, "irc-serve: unknown option: %s\n", arg);
            return -1;
        } else {
            rc = parse_port(arg, &o->port);
            if (rc != 0 || o->have_port) {
                fprintf(stderr, "irc-serve: bad port argument: %s\n", arg);
                return -1;
            }
            o->have_port = 1;
            continue;
        }

        if (strcmp(arg, "--name") == 0) {
            o->name = value;
        } else if (strcmp(arg, "--secret") == 0) {
            o->secret = value;
        } else {
            if (o->npeers >= NODE_MAX_PEERS) {
                fprintf(stderr, "irc-serve: at most %d --peer options\n",
                        NODE_MAX_PEERS);
                return -1;
            }
            if (parse_peer(value, &o->peers[o->npeers]) != 0) {
                fprintf(stderr, "irc-serve: bad --peer argument: %s\n", value);
                fprintf(stderr, "  expected NAME,HOST,PORT\n");
                return -1;
            }
            o->npeers++;
        }
    }
    return 0;
}

/* Resolve one configured peer and hand the address to the link table.
 *
 * THE ONLY getaddrinfo IN THIS TREE, and that is the point of it being a
 * function with a name rather than a call: 3.4 forbids a lookup in the event
 * loop, core/server.h forbids a resolution helper anywhere near server_dial(),
 * and this one is called from main() before poll() is armed. It is `static`, so
 * a future caller inside the loop would have to be written in this file --
 * which is the only place in src/ that has a before-the-loop step.
 *
 * The hints ask for a stream socket and nothing else, so a service the operator
 * did not name cannot be chosen: AI_PASSIVE is deliberately NOT set (there is
 * no wildcard peer here) and a numeric host still goes through the same path as
 * a name, so a `127.0.0.1` peer is not special-cased into a shortcut that a
 * future caller might copy for a hostname.
 *
 * The first result is used and the rest freed; see the header for why. */
static int resolve_peer(server_t *s, const node_peer_t *peer)
{
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    int rc;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    rc = getaddrinfo(peer->host, peer->port, &hints, &res);
    if (rc != 0 || res == NULL) {
        fprintf(stderr, "irc-serve: cannot resolve peer %s (%s:%s): %s\n",
                peer->name, peer->host, peer->port, gai_strerror(rc));
        return -1;
    }
    if (fed_link_configure(s, peer->name, res->ai_addr,
                           (socklen_t)res->ai_addrlen) == NULL) {
        fprintf(stderr, "irc-serve: cannot configure peer %s "
                        "(bad server name, duplicate, or no memory)\n",
                peer->name);
        freeaddrinfo(res);
        return -1;
    }
    freeaddrinfo(res);
    return 0;
}

int main(int argc, char **argv)
{
    node_opts_t opts;
    server_t srv;
    int bound;
    int i;
    int rc;

    /* Before any output: see the note on line buffering above. */
    setvbuf(stdout, NULL, _IOLBF, 0);

    rc = parse_args(argc, argv, &opts);
    if (rc != 0) {
        if (rc > 0) {
            usage(stdout, argv[0]);
            return 0;
        }
        usage(stderr, argv[0]);
        return 2;
    }

    printf("%s initializing...\n", IRC_SERVE_VERSION);

    if (install_handler(SIGTERM, on_stop_signal) != 0 ||
        install_handler(SIGINT, on_stop_signal) != 0 ||
        install_handler(SIGUSR1, on_usr1_signal) != 0) {
        perror("sigaction");
        return 1;
    }
    /* A write to a peer that has already gone must surface as EPIPE from
     * send(), which is what MSG_NOSIGNAL in connection.c relies on. */
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        perror("signal");
        return 1;
    }

    if (server_init(&srv, opts.name) != 0) {
        printf("[observable] server init failed: name=%s reason=invalid_name\n",
               opts.name);
        return 1;
    }
    /* Observable per-line framing/parse output. The node's own [observable]
     * lines are the contract described at the top of this file, so the trace
     * flag is on for the shipped binary. */
    srv.trace = 1;

    /* The command surface. Phase 2 installed nothing here, which was the
     * honest state of a node with no vocabulary: the loop accepted, framed and
     * parsed and then said nothing at all. This is the assignment rather than a
     * commands_install() helper so that what the shipped binary answers with is
     * visible at the point where it decides it. */
    srv.dispatch = commands_dispatch;

    /* The peer link, and the ORDER of these three assignments is the order the
     * federation module has to be built up in:
     *
     *   srv.dispatch = commands_dispatch  first, because fed_open() WRAPS
     *       whatever dispatch is there. The reverse order would wrap NULL and
     *       then throw away the client surface, which is the one part of this
     *       node that already works.
     *   fed_open()     then, for the secret and the inbound FEDERATE seam.
     *   srv.on_tick = fed_tick  last, and as a VISIBLE assignment rather than
     *       something fed_open() did behind a door. 3.4's file map puts link
     *       liveness on the tick, and a reader of this function should be able
     *       to see that without opening another file -- the same reason the
     *       command surface is assigned here rather than in a helper.
     *
     * fed_open() is called even with no --peer, because a node with no
     * configured peers still has to be able to be DIALLED: 2.3 says a link
     * establishes when EITHER side connects, and the accepting side is the one
     * half that needs no configuration. */
    if (fed_open(&srv, opts.secret) != 0) {
        printf("[observable] server init failed: name=%s "
               "reason=federation_open\n", opts.name);
        server_shutdown(&srv);
        return 1;
    }
    srv.on_tick = fed_tick;

    /* Resolve and configure the peers, still before the loop. */
    for (i = 0; i < opts.npeers; i++) {
        if (resolve_peer(&srv, &opts.peers[i]) != 0) {
            server_shutdown(&srv);
            return 1;
        }
    }

    if (server_listen(&srv, opts.port) != 0) {
        printf("[observable] server startup failed: port=%d reason=%s\n",
               opts.port, strerror(errno));
        server_shutdown(&srv);
        return 1;
    }

    /* Read the port back rather than echoing the argument: with port 0 the
     * argument is not the port, and a caller that cannot learn the real one
     * cannot connect. */
    bound = server_port(&srv);
    if (bound < 0) {
        printf("[observable] server startup failed: reason=getsockname\n");
        server_shutdown(&srv);
        return 1;
    }
    printf("[observable] tcp_bind: port=%d fd=%d state=LISTENING\n",
           bound, srv.listen_fd);
    printf("[observable] server initialized: name=%s epoch=%llu peers=%d "
           "secret=%s\n",
           opts.name, (unsigned long long)srv.epoch,
           (int)server_link_count(&srv),
           (opts.secret[0] == '\0') ? "none" : "set");

    /* Readiness: emitted after the listener is up and immediately before the
     * loop is armed, so anything waiting on this line is talking to a serving
     * node. */
    printf("[observable] loop_running: listener_fd=%d tick_ms=%d state=ARMED\n",
           srv.listen_fd, POLL_TICK_MS);
    fflush(stdout);

    rc = poll_loop_run(&srv);
    if (rc != 0) {
        printf("[observable] loop_error: state=FAILED\n");
    }

    /* Shutdown BEFORE reporting. server_shutdown() closes every connection
     * still registered, so the numbers printed here describe the node as it
     * actually finished, not a snapshot taken mid-teardown with connections
     * still open. */
    server_shutdown(&srv);

    printf("[observable] loop_stats: ticks=%llu eintr=%llu accepted=%llu "
           "closed=%llu lines=%llu parse_reject=%llu frame_error=%llu "
           "writeq_overflow=%llu write_error=%llu partial_writes=%llu "
           "rejected_fd=%llu pass_seen=%llu reply_refused=%llu "
           "fed_rejected=%llu fed_duplicate=%llu fed_hs_timeout=%llu "
           "fed_dead=%llu fed_preauth_drop=%llu fed_hop_drop=%llu "
           "fed_own_origin=%llu fed_untagged_relay=%llu "
           "fed_unknown_verb=%llu fed_verb_deferred=%llu fed_malformed=%llu "
           "fed_dup_drop=%llu fed_dedup_dup=%llu fed_squit_self=%llu "
           "burst_refused=%llu burst_abandoned=%llu burst_truncated=%llu "
           "topic_cache_full=%llu\n",
           (unsigned long long)srv.n_ticks, (unsigned long long)srv.n_eintr,
           (unsigned long long)srv.n_accepted, (unsigned long long)srv.n_closed,
           (unsigned long long)srv.n_lines,
           (unsigned long long)srv.n_parse_reject,
           (unsigned long long)srv.n_frame_error,
           (unsigned long long)srv.n_writeq_overflow,
           (unsigned long long)srv.n_write_error,
           (unsigned long long)srv.n_partial_writes,
           (unsigned long long)srv.n_rejected_fd,
           (unsigned long long)srv.n_pass_seen,
           (unsigned long long)srv.n_reply_refused,
           (unsigned long long)srv.n_link_rejected,
           (unsigned long long)srv.n_link_duplicate,
           (unsigned long long)srv.n_fed_hs_timeout,
           (unsigned long long)srv.n_fed_dead,
           (unsigned long long)srv.n_fed_preauth_drop,
           (unsigned long long)srv.n_fed_hop_drop,
           (unsigned long long)srv.n_fed_own_origin,
           (unsigned long long)srv.n_fed_untagged_relay,
           (unsigned long long)srv.n_fed_unknown_verb,
           (unsigned long long)srv.n_fed_verb_deferred,
           (unsigned long long)srv.n_fed_malformed,
           (unsigned long long)srv.n_fed_dup_drop,
           (unsigned long long)srv.n_fed_dedup_dup,
           (unsigned long long)srv.n_fed_squit_self,
           (unsigned long long)srv.n_burst_refused,
           (unsigned long long)srv.n_burst_abandoned,
           (unsigned long long)srv.n_burst_truncated,
           (unsigned long long)srv.n_topic_cache_full);

    /* The link table itself, and last, after the counters: 8 asks for "a way to
     * dump peers and their FSM states" and the state is what the counters are
     * about. It is printed at shutdown as well as on every event, so a node that
     * exits cleanly still leaves a record of what it was linked to. */
    fed_dump(&srv, "shutdown");

    /* exit 0 even after a loop error: a clean shutdown is what a test asserts,
     * and a failed loop has already said so on stdout. */
    printf("[observable] server_shutdown: state=STOPPED\n");
    return (rc == 0) ? 0 : 1;
}
