/* test_fed_isolation.c -- issue #173: two server_t in one process share nothing.
 *
 * ---------------------------------------------------------------------------
 * WHAT IS ASSERTED, AND WHY IT IS A UNIT TEST
 * ---------------------------------------------------------------------------
 * Every per-node fact that used to be a file-static global -- the federation
 * secret, the four link timers, the three reconnect intervals, the per-reason
 * rejection breakdown, the burst byte budget and its shadow, and the resume
 * window -- is exercised here on TWO nodes in ONE process, with different
 * values, asserting that neither node sees the other's. No sockets, no
 * children, no loop: links are configured with a loopback address that is
 * never dialled, and lines are parsed from strings and applied directly.
 *
 * fed_send_shutdown() plus server_shutdown() share one assertion: the goodbye
 * is silent and idempotent on a node with no ESTABLISHED links, whether it is
 * reached directly or through the shutdown, and a node that is shut down can
 * be re-opened -- which is the observable half of fed_close() unwrapping the
 * dispatch fed_open() installed. A goodbye carried on a live link is already
 * covered by the integration suite; what belongs here is that the two paths
 * agree where no link is up.
 */
#include <arpa/inet.h>
#include <assert.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#include "core/connection.h"
#include "core/message.h"
#include "core/resume.h"
#include "core/server.h"
#include "federation/burst.h"
#include "federation/link.h"

#define SECRET_A "alpha-secret-value-1"
#define SECRET_B "beta-secret-value-2"

/* A configured-but-never-dialled peer: a pre-resolved loopback address that
 * no tick ever acts on, because the test never installs fed_tick. */
static server_link_t *configure_loopback(server_t *s, const char *name)
{
    struct sockaddr_in sa;

    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port = htons(6668);
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    return fed_link_configure(s, name, (const struct sockaddr *)&sa,
                              (socklen_t)sizeof sa);
}

int main(void)
{
    server_t a;
    server_t b;
    server_link_t *la;
    server_link_t *lb;
    conn_t *c;
    message_t m;
    uint64_t peer_epoch = 0u;
    char line[512];

    assert(server_init(&a, "irc.a") == 0);
    assert(server_init(&b, "irc.b") == 0);

    /* --- two opens in one process, previously the second was refused ------ */
    assert(fed_open(&a, SECRET_A) == 0);
    assert(fed_open(&b, SECRET_B) == 0);
    /* ...while a second open of the SAME node still is: it would wrap the
     * wrapper and recurse. */
    assert(fed_open(&a, SECRET_A) != 0);
    assert(strcmp(a.fed_secret, SECRET_A) == 0);
    assert(strcmp(b.fed_secret, SECRET_B) == 0);

    /* --- the secret check answers per node -------------------------------- */
    (void)snprintf(line, sizeof line, ":irc.p FEDERATE irc.p 7 %s %s",
                    SECRET_A, IRC_SERVE_VERSION);
    assert(message_parse(line, &m) == 0);
    assert(fed_check_federate(&a, NULL, &m, a.fed_secret, &peer_epoch)
           == FED_OK);
    assert(peer_epoch == 7u);
    assert(fed_check_federate(&b, NULL, &m, b.fed_secret, NULL)
           == FED_BAD_SECRET);
    message_free(&m);

    /* --- a wrong secret is counted on the node it arrived on, and only ---- */
    c = conn_new(-1, CONN_CLIENT);
    assert(c != NULL);
    (void)snprintf(line, sizeof line,
                    ":irc.p FEDERATE irc.p 7 wrong-secret-value %s",
                    IRC_SERVE_VERSION);
    assert(message_parse(line, &m) == 0);
    fed_on_federate(&a, c, &m);
    message_free(&m);
    assert(a.n_link_rejected == 1u);
    assert(a.fed_rejected[FED_BAD_SECRET] == 1u);
    assert(b.n_link_rejected == 0u);
    assert(b.fed_rejected[FED_BAD_SECRET] == 0u);
    conn_free(c);

    /* --- timeouts: an override moves one node and not the other ----------- */
    fed_set_timeouts(&a, 0, 100u, 0, 0);
    fed_set_timeouts(&b, 0, 200u, 0, 0);
    assert(fed_hs_due(&a, 1000, 1099) == 0);
    assert(fed_hs_due(&a, 1000, 1100) != 0);
    assert(fed_hs_due(&b, 1000, 1100) == 0);
    assert(fed_hs_due(&b, 1000, 1200) != 0);

    /* --- the reconnect ladder and the advertise period likewise ------------ */
    fed_set_retry(&a, 50u, 500u, 2u);
    fed_set_retry(&b, 60u, 600u, 5u);
    assert(a.fed_retry_base_ms == 50u);
    assert(b.fed_retry_base_ms == 60u);
    assert(a.fed_retry_max_ms == 500u);
    assert(b.fed_retry_max_ms == 600u);
    assert(a.fed_retry_budget == 2u);
    assert(b.fed_retry_budget == 5u);
    fed_set_advertise_interval(&a, 111u);
    fed_set_advertise_interval(&b, 222u);
    assert(a.fed_advertise_ms == 111u);
    assert(b.fed_advertise_ms == 222u);

    /* --- the burst budget is per node -------------------------------------- */
    fed_burst_set_max_bytes(&a, 1001u);
    assert(a.burst_max_bytes == 1001u);
    assert(b.burst_max_bytes == (size_t)IRC_BURST_MAX_BYTES);

    /* --- the shadow: a transaction open on a is invisible on b ------------ */
    la = configure_loopback(&a, "irc.x");
    lb = configure_loopback(&b, "irc.y");
    assert(la != NULL && lb != NULL);
    (void)snprintf(line, sizeof line,
                    "@irc-serve-origin=irc.x;irc-serve-epoch=7;irc-serve-id=1;"
                    "irc-serve-hops=0 :irc.x SBURST 7 0");
    assert(message_parse(line, &m) == 0);
    assert(fed_burst_apply(&a, la, &m) == 0);
    message_free(&m);
    assert(a.burst != NULL);
    assert(b.burst == NULL);
    /* A record stages on the node whose transaction is open ... */
    (void)snprintf(line, sizeof line,
                    "@irc-serve-origin=irc.x;irc-serve-epoch=7;irc-serve-id=2;"
                    "irc-serve-hops=0 :irc.x SBURSTN bob u h - 1 :hi");
    assert(message_parse(line, &m) == 0);
    assert(fed_burst_apply(&a, la, &m) == 0);
    message_free(&m);
    /* ... and the same record on the other node is a stray line, counted as
     * malformed there and nowhere else. */
    assert(message_parse(line, &m) == 0);
    assert(fed_burst_apply(&b, lb, &m) != 0);
    message_free(&m);
    assert(b.n_fed_malformed == 1u);
    assert(a.n_fed_malformed == 0u);

    /* --- the resume window is per node ------------------------------------- */
    resume_set_window(&a, 800u);
    resume_set_window(&b, 4000u);
    assert(resume_window_ms(&a) == 800u);
    assert(resume_window_ms(&b) == 4000u);
    assert(resume_hold_ms(&a) == 1000u); /* 800/2, clamped to the floor */
    assert(resume_hold_ms(&b) == 2000u); /* 4000/2, inside the clamps */
    assert(resume_sweep(&a, server_now_ms()) == 0u);
    assert(resume_sweep(&b, server_now_ms()) == 0u);

    /* --- the goodbye: silent and idempotent with no link up ---------------- */
    assert(fed_send_shutdown(&a, NULL) == 0);
    assert(fed_send_shutdown(&a, "restart") == 0);
    assert(fed_send_shutdown(&b, NULL) == 0);

    /* --- shutdown, then re-open: the dispatch was unwrapped ---------------- */
    server_shutdown(&a);
    server_shutdown(&b);
    assert(fed_open(&a, "third-secret-value-3") == 0);
    assert(strcmp(a.fed_secret, "third-secret-value-3") == 0);
    server_shutdown(&a);

    printf("ok: fed_isolation\n");
    return 0;
}
