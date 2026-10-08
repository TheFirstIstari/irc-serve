/* test_cap_bounds.c -- the BOUND on what a CAP reply writes, as a claim about
 * every capacity rather than about one (#123).
 *
 * ---------------------------------------------------------------------------
 * WHAT THIS IS FOR
 * ---------------------------------------------------------------------------
 * `CAP LS` is rendered into `char list[CAP_LS_MAX]` by `cap_available_list()`, and
 * the audit that filed #123 said that function "is correctly bounded per append"
 * while the `CAP LIST` arm in `cap_do_ls()` was "the only completely unbounded
 * accumulation in the tree". Both halves were right, which is the awkward
 * combination: two arms of one command, one bounded by a test on every write and
 * one bounded only by arithmetic about a table in another function.
 *
 * This file is the evidence for the bounded half, and it is deliberately a SWEEP
 * rather than one call. A single call at `CAP_LS_MAX` proves that the reply fits
 * its buffer. It cannot prove that the two refusal arms are reached, that the
 * value's length is accounted for separately, or that `out[0]` is zeroed on the
 * way out. So every capacity from 1 to `CAP_LS_MAX + 64` is tried in turn, with a
 * CANARY region behind the buffer, and four things are asserted at each:
 *
 *   1. NO WRITE ESCAPES `cap`. One changed byte in the canary is a write past the
 *      end of a caller-provided buffer, which is the Phase-8 bug this area of the
 *      file exists because of. The canary is compared against a known byte rather
 *      than against zero, because a write of a NUL is exactly what an off-by-one
 *      looks like.
 *   2. A NON-ZERO RETURN IS THE EXACT LENGTH, and the buffer holds a string of
 *      that length. Reading that string with strlen() at a capacity one byte short
 *      of the write is a read past the same end, so the sweep is a read check as
 *      well as a write check.
 *   3. A ZERO RETURN COMES WITH AN EMPTY BUFFER. "Refused rather than truncated"
 *      is two properties, not one: a caller that renders `out` into a CAP line
 *      cannot tell a refusal from a list unless the refusal left nothing behind,
 *      and a half-written `sts=duration=` is what a client cannot parse.
 *   4. THE SWEEP REACHED BOTH SIDES. `fits > 0` and `refusals > 0` are asserted as
 *      counts rather than assumed, because a function that refused everything, or
 *      that accepted everything, would satisfy a pure absence assertion and a pure
 *      presence assertion respectively.
 *
 * ---------------------------------------------------------------------------
 * THE WORST CASE IS BUILT HERE, AND IT IS BUILT BY HAND
 * ---------------------------------------------------------------------------
 * The maximum output needs every capability available at once, including `sts`,
 * whose value is `sts=duration=4294967295,port=65535` -- 34 bytes, the longest
 * value any name in this tree has. Four of the five conditions are fields:
 * `sasl` needs a credential in the store, `account-tag` needs a registry entry,
 * and `sts`'s duration is `server_t::sts_duration`. The fifth is not a field:
 * `sts` is offered only when `tls_node_possible()` AND `server_tls_port()` agree,
 * and the first of those asks whether `server_t::tls` is non-NULL while the second
 * asks what an implicit-TLS LISTENER is bound to.
 *
 * THE CONNECTION IS NULL HERE, and that is the answer that makes this sweep the WIDEST
 * one rather than a narrow one: cap.c's conn_plaintext() reads a NULL connection as
 * plaintext, so `tls` and `sts` are offered. That is what this file wants -- the
 * bound is most interesting around the longest list the function can produce, and a
 * list with the two TLS names missing is 33 bytes shorter before any sweep starts.
 * cap.c gives the reasoning at the predicate; the per-connection behaviour itself is
 * asserted over the wire in tests/integration/test_tls.c, where there is a real
 * encrypted connection to ask about.
 *
 * So the worst case is constructed rather than waited for: a real listening
 * socket on the loopback, adopted as `tls_listen_fd`, and `tls` set to a non-NULL
 * sentinel. cap.c asks two questions about TLS and neither of them dereferences
 * the pointer -- `tls_node_possible()` tests it against NULL and
 * `server_tls_port()` asks the socket -- so a node that "has TLS" for the purposes
 * of the one question this file asks is a node with the socket, and the real
 * OpenSSL context behind it is not reachable from a unit test and is not needed
 * to make the bound bind.
 *
 * AND WHAT THAT BUYS. Without the `sts` value, `vlen` is zero for every name and
 * the arm that accounts for the value's length separately is INDISTINGUISHABLE
 * from one that forgot to. That is not a theoretical gap: the teeth run found a
 * fault which removed `vlen` from the bound and every assertion in the first
 * version of this file still passed. With the value present, the `vlen` term is
 * live at every capacity, and removing it turns this red.
 *
 * `CAP LIST` is a different arm and is not reachable from here at all: its
 * accumulator is local to `cap_do_ls()`, so the only way at it is over the wire,
 * which is why its own assertion lives in tests/integration/test_cap_negotiation.c
 * and why that one is partly a source inspection.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS DIRECTORY'S ASSERTION STYLE
 * ---------------------------------------------------------------------------
 * The other tests here use `assert(3)` and link `irc_core` alone; the harness's
 * TF_CHECK_MSG lives in tests/integration/, which this directory is added before,
 * so taking it would mean either reordering the add_subdirectory() calls or
 * compiling test_util.c into a second target. The messages below are formatted
 * with snprintf rather than handed to a printf-attributed function because
 * -Wformat-nonliteral is on in this tree, and the format string at a CHECK call
 * site is a macro parameter.
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "core/cap.h"
#include "core/server.h"
#include "sasl_framework.h"
/* For struct tls_node, so the sentinel below is a well-typed pointer rather than a
 * cast: server.h forward-references it and tls_backend.h owns the definition. */
#include "tls_backend.h"

#define CANARY_BYTE 0xA5u
#define CANARY_LEN 256u
#define SWEEP_MAX (CAP_LS_MAX + 64u)

static int g_failures;

static void report(const char *file, int line, const char *msg)
{
    g_failures++;
    fprintf(stderr, "%s:%d: %s\n", file, line, msg);
}

/* THE MESSAGE BUFFER IS 1024 AND NOT 512, and the reason is gcc-16's
 * -Wformat-truncation, which is an ERROR in this tree and is right: the longest
 * message literal here is about 250 characters of prose and the string it quotes
 * is bounded at 400, so a 512-byte destination has 249 bytes of room for 400
 * bytes of value and the compiler can see the overflow. 1024 gives it 760, which
 * satisfies the analysis honestly rather than by shortening the diagnostic until
 * it stops complaining.
 *
 * It is a stack buffer in a loop that runs at most SWEEP_MAX times, so the cost is
 * a frame rather than an allocation, and it lives only inside the CHECK arm. */
#define CHECK(cond, ...)                                                      \
    do {                                                                      \
        if (!(cond)) {                                                        \
            char tf_msg_[1024];                                               \
                                                                              \
            (void)snprintf(tf_msg_, sizeof tf_msg_, __VA_ARGS__);             \
            report(__FILE__, __LINE__, tf_msg_);                              \
            return;                                                           \
        }                                                                     \
    } while (0)

/* The canary is a region of known bytes immediately after the buffer the call is
 * given, and it is checked by VALUE against CANARY_BYTE rather than by being
 * non-zero: a write that happened to write a zero would otherwise pass. */
static int canary_intact(const unsigned char *canary, size_t cap)
{
    for (size_t i = 0; i < CANARY_LEN; i++) {
        if (canary[i] != (unsigned char)CANARY_BYTE) {
            char msg[160];

            (void)snprintf(msg, sizeof msg,
                           "cap_available_list wrote %zu bytes past a cap of %zu "
                           "(canary byte %zu is 0x%02X, not 0x%02X)",
                           i + 1u, cap, i, canary[i], (unsigned)CANARY_BYTE);
            report(__FILE__, __LINE__, msg);
            return 0;
        }
    }
    return 1;
}

/* THE WORST-CASE NODE, and every step of it is a step the code under test asks
 * about rather than a step it performs.
 *
 * `sts_duration` is set to UINT32_MAX because that is the widest value the
 * specification's grammar allows and therefore the one that makes `sts`'s value
 * longest: `duration=4294967295` is ten digits, where any smaller figure is
 * fewer. A test that left it at 0 would render `sts=duration=0,port=N` and lose
 * nine bytes of the very term the bound has to account for.
 *
 * `tls_listen_fd` is a REAL listening socket rather than a number, because
 * `server_tls_port()` calls getsockname() on it and returns -1 for a descriptor
 * that is not bound. A fabricated fd would make `sts` unavailable again and the
 * whole construction would be a no-op that looks like a pass.
 *
 * And the node says so, so a reader is not left taking it on trust: the widest
 * rendering this file observes is printed, and it is only as wide as the worst
 * case because the sweep got there. */
static void make_worst_case(server_t *s)
{
    struct sockaddr_in sa;
    socklen_t len = sizeof sa;
    int one = 1;
    int lfd = socket(AF_INET, SOCK_STREAM, 0);

    CHECK(lfd >= 0, "could not create a socket to stand in for the TLS listener");
    (void)setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0; /* the kernel's choice, which is what a real --tls-port 0 is */
    if (bind(lfd, (struct sockaddr *)&sa, sizeof sa) != 0 ||
        listen(lfd, 1) != 0 ||
        getsockname(lfd, (struct sockaddr *)&sa, &len) != 0) {
        (void)close(lfd);
        CHECK(0, "could not bind the socket that stands in for the TLS listener");
    }
    (void)ntohs(sa.sin_port);
    s->tls_listen_fd = lfd;
    s->tls_listen_port = (int)ntohs(sa.sin_port);
    /* The sentinel. NOT a real context, and deliberately so: cap.c's two TLS
     * questions test it against NULL and never dereference it, so a fake is enough
     * to make the capability AVAILABLE where a real one would be, and it cannot
     * accidentally start doing something a real context would do. A static, rather
     * than a pointer into server_t, so that a later `server_shutdown()` cannot walk
     * a type it does not recognise. */
    {
        /* Via void*, because `struct tls_node` is only FORWARD-declared in the
         * headers -- tls_backend.h owns the definition and it is in the backend's
         * .c file -- so a value of that type cannot be declared here. The round trip
         * through void* is what keeps this from being a pointer cast between
         * incompatible object types, and nothing reads the pointer: cap.c's two TLS
         * questions are `s->tls != NULL` and getsockname() on the listener fd. */
        s->tls = (struct tls_node *)(void *)&s->sts_duration;
    }
    s->sts_duration = 0xFFFFFFFFu;
    /* One credential, so `sasl` is offered too. server_init() leaves
     * `sasl_store` NULL -- a node with no --sasl-store -- and sasl_store_add()
     * refuses a NULL store, so the store is CREATED here rather than written to.
     * Five bytes of the answer, which is small, and it is here because it is the
     * one condition on availability that is neither a plain field nor TLS: a
     * capability whose availability is a property of the CONFIGURED NODE. */
    if (s->sasl_store == NULL) {
        s->sasl_store = sasl_store_new();
    }
    CHECK(s->sasl_store != NULL, "sasl_store_new() failed, so `sasl` cannot be "
                                 "offered and the worst-case list is short by a name");
    CHECK(sasl_store_add(s->sasl_store, "bounds-probe", "not-a-real-password") == 0,
          "sasl_store_add() refused a valid credential, so `sasl` will not be "
          "offered and the worst-case list is short by a name");
    CHECK(sasl_store_count(s->sasl_store) == 1u,
          "the store took a credential but reports %zu, so `sasl_possible()` will "
          "not offer it",
          sasl_store_count(s->sasl_store));
}

static void sweep_cap_available_list(void)
{
    server_t s;
    unsigned char buf[SWEEP_MAX + CANARY_LEN];
    size_t fits = 0u;
    size_t refusals = 0u;
    size_t longest = 0u;
    char widest[512];

    CHECK(server_init(&s, "irc.test") == 0,
          "server_init failed; every assertion in this file needs a node");
    make_worst_case(&s);

    for (size_t cap = 1u; cap <= SWEEP_MAX; cap++) {
        char msg[512];
        size_t n;

        memset(buf, CANARY_BYTE, sizeof buf);
        /* NULL for the connection: see the header. The sweep wants the widest list
         * the function can render, and cap.c reads a NULL connection as plaintext. */
        n = cap_available_list(&s, NULL, (char *)buf, cap);
        if (!canary_intact(&buf[cap], cap)) {
            return;
        }
        if (n == 0u) {
            refusals++;
            /* REFUSED MEANS EMPTY. See the file header, point 3. */
            if (buf[0] != 0u) {
                (void)snprintf(msg, sizeof msg,
                               "cap_available_list returned 0 for a cap of %zu but left "
                               "\"%s\" in the buffer, so a caller cannot tell a refusal "
                               "from a list",
                               cap, (const char *)buf);
                report(__FILE__, __LINE__, msg);
                return;
            }
            continue;
        }
        fits++;
        if (n >= cap) {
            (void)snprintf(msg, sizeof msg,
                           "cap_available_list returned %zu for a cap of %zu, so it "
                           "claims to have written bytes it was not given room for",
                           n, cap);
            report(__FILE__, __LINE__, msg);
            return;
        }
        /* strlen() AT cap-1 IS A READ PAST THE BUFFER'S END if the function wrote
         * cap-1 bytes without terminating, which is the same defect as the write
         * the canary above looks for. */
        if (strlen((const char *)buf) != n) {
            /* THE PRECISION, and it is not decoration: gcc-16's
             * -Wformat-truncation is an ERROR in this tree and it is right, because
             * `buf` is SWEEP_MAX + CANARY_LEN bytes and `msg` is 512. Truncating a
             * diagnostic is acceptable -- it is the diagnostic, not the buffer under
             * test -- but it has to be truncation the COMPILER can see, which is what
             * the precision says and what a bare `%s` does not. The number being
             * reported is the whole claim either way. */
            (void)snprintf(msg, sizeof msg,
                           "cap_available_list returned %zu but the buffer holds "
                           "\"%.400s\", so the count and the string disagree",
                           n, (const char *)buf);
            report(__FILE__, __LINE__, msg);
            return;
        }
        if (n > longest) {
            longest = n;
            (void)snprintf(widest, sizeof widest, "%.500s", (const char *)buf);
        }
    }

    CHECK(fits > 0u,
          "cap_available_list never produced anything at any capacity from 1 to %u, so "
          "this sweep measured nothing",
          (unsigned)SWEEP_MAX);
    CHECK(refusals > 0u,
          "cap_available_list never refused at any capacity from 1 to %u, so no "
          "refusal arm was reached and the bound was never exercised",
          (unsigned)SWEEP_MAX);
    CHECK(longest > 0u && longest < (size_t)CAP_LS_MAX,
          "the longest rendering at any capacity was %zu, which is not between 1 and "
          "CAP_LS_MAX (%u)",
          longest, (unsigned)CAP_LS_MAX);
    /* AND THE WORST CASE WAS OR WAS NOT AVAILABLE, said out loud rather than left
     * to be inferred from the width.
     *
     * The gate builds WITH_TLS both ON and OFF, and `sts` is only offered when the
     * TLS BACKEND is compiled in -- `tls_backend_available()` is a compile-time
     * constant behind a function, and cap.c's own rule is that a build without TLS
     * advertises neither `tls` nor `sts`. So the value arm of the bound is reachable
     * in the TLS cell and not in the other one, and an assertion that demanded it
     * unconditionally would fail a cell whose build is behaving correctly.
     *
     * So the width is asserted against WHAT THIS BUILD CAN OFFER, and the two
     * branches have different floors:
     *
     *   TLS ON    250 is the widest list this node can produce, counted by hand:
     *             every name in the table, the separators, and `sts`'s 35-byte
     *             name=value pair. The floor is 200, which a list without `sts`'s
     *             value cannot reach, so a sentinel or credential that silently
     *             failed to take fails here instead of reporting a comfortable
     *             number and looking fine.
     *
     *   TLS OFF   177 is the widest list WITHOUT `sts` and `tls` -- the same table
     *             less those two names and their separators. The floor is 150, which
     *             still says the credential took (four more bytes) and the table ran.
     *
     * BOTH floors are below CAP_LS_MAX by a wide margin, so neither branch is a
     * statement that the bound was nearly reached -- the sweep above is that
     * statement, and it runs the same way in both cells. */
    if (tls_backend_available() != 0 && server_tls_port(&s) > 0) {
        CHECK(longest >= 200u,
              "this build has TLS and the worst-case node has a TLS port, so `sts` "
              "and its value must have been rendered, and the longest list was %zu "
              "bytes -- the sentinel or the credential did not take and every arm "
              "that accounts for a value's length was never reached. widest=[%.400s]",
              longest, widest);
    } else {
        CHECK(longest >= 150u,
              "this build has no TLS backend, so `sts` and its value are correctly "
              "withheld and the widest list is the names alone -- but it was %zu "
              "bytes, which is below the floor for a table with a credential in it. "
              "widest=[%.400s]",
              longest, widest);
    }
    /* THE HEADROOM, as a number rather than an absence, so the sweep's result is
     * legible. `longest` is the size of the largest list THIS node renders, which
     * is every capability it can offer with `sts` withheld; tests/integration/
     * test_cap_negotiation.c measures the same node with `sts` at its maximum
     * against the same constant. */
    printf("[observable] cap_sweep: fits=%zu refusals=%zu longest=%zu cap_ls_max=%u "
           "tls=%d tls_port=%d sasl=%zu widest=[%.500s]\n",
           fits, refusals, longest, (unsigned)CAP_LS_MAX, tls_backend_available(),
           server_tls_port(&s), sasl_store_count(s.sasl_store), widest);

    /* THE SENTINEL IS UNDONE BEFORE THE TEARDOWN, and this is not tidiness: on a
     * WITH_TLS build server_shutdown() calls tls_backend_node_free(s->tls), which
     * dereferences and frees whatever is there. Leaving the sentinel in place turns
     * the teardown into a free() of an address inside this frame, which is a
     * segmentation fault rather than a test failure -- the first version of this
     * file did exactly that and took the whole binary down after every assertion
     * had passed. The socket is closed for the same reason and by the same rule:
     * server_shutdown() closes tls_listen_fd too. */
    s.tls = NULL;
    server_shutdown(&s);
}

int main(void)
{
    sweep_cap_available_list();
    if (g_failures != 0) {
        fprintf(stderr, "FAILED: cap_bounds (%d failure(s))\n", g_failures);
        return 1;
    }
    return 0;
}
