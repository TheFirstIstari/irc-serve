/* test_peer_tls.c -- Phase 12 item 5: TLS on a peer link, and the mixed-mesh
 * decision.
 *
 * ===========================================================================
 * THE DECISION THIS FILE ASSERTS, stated before the assertions
 * ===========================================================================
 * A MESH MAY MIX. A node configured with TLS may hold some links that carry it and
 * some that do not, and nothing in this phase requires otherwise. Two reasons,
 * and the second is the important one:
 *
 *   1. Rolling a mesh onto TLS one link at a time is the only deployment that
 *      works. A mesh where every link must be TLS before any of them may be is a
 *      mesh where the first --peer-tls cannot be deployed without taking the mesh
 *      down, and a change that requires a window is a change that does not get made.
 *
 *   2. A LINK'S MODE IS STICKY, and that is what makes the mixing safe.
 *      `server_link_t::require_tls` is set once from the operator's command line
 *      and is NEVER CLEARED -- not by a tick, not by the retry arm, not by
 *      fed_link_reset(), not by fed_link_set_tls(0). A link that was TLS re-dials
 *      with TLS or does not come back. THAT is the downgrade answer, and it is a
 *      structural property rather than a rule somebody has to remember: there is no
 *      code path that turns it off.
 *
 * SO WHAT A DOWNGRADE WOULD TAKE, and this is the part worth being precise about:
 *
 *   An attacker who wants this node's link to a TLS peer in the clear must (a)
 *   stop the TLS handshake from completing on every retry -- so they must be on the
 *   path for the handshake, not merely for the retry -- and (b) have the peer
 *   accept a plaintext link with that peer's NAME, because the shared secret is
 *   what identifies a peer and it is presented in the clear on a plaintext link.
 *   (b) is not free: the link must reach ESTABLISHED with the right name and epoch,
 *   and a node that has a link to that name already refuses a second claim with
 *   DUPLICATE_LINK. So the downgrade is not "be the network", it is "be the network
 *   for the handshake AND present a valid claim for a name this mesh already has",
 *   which is a compromised peer rather than a network position.
 *
 *   AGAINST THAT: the mixed mesh means a plaintext link DOES carry the shared
 *   federation secret in the clear, so the secret is readable by anyone on that
 *   path, and a secret this mesh also uses for its TLS links is a secret whose
 *   compromise is not confined to the plaintext link. An operator running a mixed
 *   mesh is accepting that, and the honest thing is to say it rather than let
 *   "mixed is supported" read as "mixed is free". The cost of NOT mixing is the
 *   coordinated-cutover problem above; the cost of mixing is a wider blast radius
 *   for the secret. That is the trade and the operator makes it.
 *
 * ===========================================================================
 * WHAT THESE TESTS RUN AGAINST, AND WHY IT IS NOT THE OBVIOUS TOPOLOGY
 * ===========================================================================
 * The peer link rides the IMPLICIT-TLS PORT, not the plaintext one, and that is not
 * a convenience:
 *
 *   A node cannot tell a TLS peer from a plaintext client by sniffing. Any client
 *   that sends something other than a TLS ClientHello first defeats a detector, and
 *   a detector that guesses is a downgrade waiting to be asked for. So the node
 *   does not guess: an inbound peer link over TLS arrives on --tls-port, where every
 *   byte is TLS before anything is interpreted, and it is protected by exactly the
 *   mechanism a client's is.
 *
 *   An OUTBOUND link configured with --peer-tls is enforced properly: the handshake
 *   is started on the connected socket, the peer's certificate is verified against
 *   --tls-ca AND against the link's server NAME, and a failure closes the link and
 *   spends a retry rather than continuing in the clear. That half is the one with
 *   teeth, and the wrong-CA case below proves it.
 */
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

#include "harness/node_fixture.h"
#include "harness/test_util.h"
#include "harness/tls_fixture.h"

/* THE FIXTURE'S DIRECTORY AND THE PATHS BUILT FROM IT.
 *
 * PF_PATH is deliberately LARGER than PF_DIR_MAX, and that is arithmetic rather
 * than taste. Every path below is `"%s/<name>"` where the first %s is `dir`, so the
 * compiler has to prove PF_DIR_MAX + strlen(name) + 1 fits the destination -- and
 * with a same-sized destination it cannot, so gcc-16 refuses to compile under
 * -Werror while Apple clang 21 and upstream clang 23 do not diagnose it at all.
 *
 * Three compilers disagreeing about whether a construct is a defect is exactly the
 * situation where satisfying the strictest is right: the alternative is a
 * -Wno-format-truncation suppression, and a suppression is invisible to a reader of
 * the build output and permanent. 128 bytes is room for the longest suffix used
 * here (`/wrongca.crt`). */
#define PF_DIR_MAX 512
#define PF_PATH (PF_DIR_MAX + 128)

static int failures;

static void check(int cond, const char *what, const char *detail)
{
    if (cond != 0) {
        printf("ok: %s\n", what);
        return;
    }
    failures++;
    printf("FAILED: %s\n  %s\n", what, (detail != NULL) ? detail : "");
}

static void cert_dir(char *out, size_t cap)
{
    const char *base = getenv("IRCSERVE_BUILD_DIR");

    if (base == NULL) {
        base = "/tmp";
    }
    snprintf(out, cap, "%s/peer-tls-%ld", base, (long)getpid());
    (void)mkdir(out, 0700);
}

/* ---------------------------------------------------------------------------
 * THE ARGUMENT BUILDER
 * ---------------------------------------------------------------------------
 * Every spawn here passes six or seven options, and the first version of this file
 * hand-indexed them into `char *av[16]` arrays with the option NAMES in separate
 * local char[] variables. That shape failed three ways in one run, all of them
 * mine:
 *
 *   - an option's value and the NEXT option's name were adjacent slots, so
 *     deleting one unused variable silently SHIFTED every later option and the node
 *     started with `--peer irc.b,127.0.0.1,PORT --tls-cert ...` and no
 *     `--peer-tls` at all. The test then reported that the link was not required to
 *     carry TLS, which was true, and the reason was a missing array slot.
 *   - the arrays were not NULL-terminated, and nf_spawn_binary_argv()'s header is
 *     explicit that a non-terminated vector is undefined. It showed up as a spawn
 *     that timed out with no child output.
 *   - one case needed an empty string to keep an index in place, which turned into
 *     `--tls-port ` and a parse error.
 *
 * A builder cannot do any of those: every option is one call, order is the order
 * written, and termination is the builder's job rather than the caller's.
 * --------------------------------------------------------------------------- */
typedef struct {
    char  *v[24];
    size_t n;
} argv_build_t;

static void ab_init(argv_build_t *b)
{
    memset(b, 0, sizeof *b);
}

static void ab_add(argv_build_t *b, const char *arg)
{
    if (b->n < sizeof b->v / sizeof b->v[0] - 1u) {
        b->v[b->n++] = (char *)(uintptr_t)(const void *)arg;
    }
}

static void ab_opt(argv_build_t *b, const char *name, const char *value)
{
    ab_add(b, name);
    ab_add(b, value);
}

/* NULL-terminated, and the NULL is set by ab_finish() rather than by the caller
 * remembering to write it -- which is the third of the three failures above. */
static char **ab_finish(argv_build_t *b)
{
    b->v[b->n] = NULL;
    return b->v;
}

/* A spawned node's implicit-TLS port, read off its own startup line. `--tls-port 0`
 * asks the kernel for an ephemeral port, so the argument is NOT the port and a
 * test that used it would dial nothing. */
static int tls_port_of(const nf_node_t *n)
{
    const char *p = strstr(n->out, "tls_port=");

    return (p != NULL) ? atoi(p + 9) : -1;
}

int main(void)
{
    char dir[PF_DIR_MAX];
    /* THE PATH BUFFERS ARE 640 AND NOT 512, and that is arithmetic rather than
     * taste. `dir` is `char dir[512]` and each of these is built as
     * `"%s/<name>"`, so the compiler has to prove 512 + strlen(name) + 1 fits --
     * and with a same-sized destination it cannot, so gcc-16 refuses to compile
     * under -Werror while Apple clang and upstream clang do not diagnose it at all.
     *
     * Three compilers that disagree about whether a construct is a defect is
     * exactly the situation where satisfying the strictest is right: the
     * alternative is a suppression, and a suppression is invisible to a reader of
     * the build output. DIR_MAX + PATH_MAX_SUFFIX_SLACK is the whole of it. */
    char a_cert[PF_PATH], a_key[PF_PATH], b_cert[PF_PATH], b_key[PF_PATH];
    char a_tls[PF_PATH];
    /* Cases 4 and 5 need four more path buffers and they are named for what they
     * hold rather than for which node uses them, because a case 4/5 fixture is
     * used by BOTH ends: B presents `digit.crt` and A is given the same file as
     * its --tls-ca. Naming them digit_* and wrongname_* is what makes that
     * symmetry readable; `b_cert`/`b_key` would suggest B owns them. Same
     * arithmetic as the buffers above: PF_PATH is PF_DIR_MAX + 128. */
    char digit_crt[PF_PATH], digit_key[PF_PATH];
    char wrong_crt[PF_PATH], wrong_key[PF_PATH];
    char buf[256];
    nf_node_t na;
    nf_node_t nb;

    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("== test_peer_tls ==\n");
    cert_dir(dir, sizeof dir);
    printf("note: TLS is %s in this build\n", (tf_tls_available() != 0) ? "COMPILED IN"
                                                                      : "NOT compiled in");
    snprintf(a_cert, sizeof a_cert, "%s/a.crt", dir);
    snprintf(a_key, sizeof a_key, "%s/a.key", dir);
    snprintf(b_cert, sizeof b_cert, "%s/b.crt", dir);
    snprintf(b_key, sizeof b_key, "%s/b.key", dir);

    /* EVERY case below is a statement about the DEFAULT build as well, and the
     * default build can be asserted on without a certificate: a node with no TLS
     * refuses --peer-tls at startup, with a named reason. That is the same shape as
     * test_tls.c's, and for the same reason -- neither branch skips. */
    if (tf_tls_available() == 0) {
        char msg[4096];
        char v0[] = "irc-serve";
        char v1[] = "0";
        char v2[] = "--name";
        char v3[] = "irc.a";
        char v4[] = "--peer";
        char v5[] = "irc.b,127.0.0.1,1";
        char v6[] = "--peer-tls";
        char v7[] = "irc.b";
        char *v[10];
        int rc;

        v[0] = v0; v[1] = v1; v[2] = v2; v[3] = v3;
        v[4] = v4; v[5] = v5; v[6] = v6; v[7] = v7;
        v[8] = NULL; v[9] = NULL;
        rc = 0;
        {
            /* run_expecting_refusal is a static in test_tls.c; this file forks its
             * own so the two do not have to share a header for one function. The
             * shape is the same and the reason is the same: a node that starts
             * normally holds the pipe open for ever, so the deadline is what
             * distinguishes a refusal from a node that came up. */
            int fds[2];
            pid_t pid = -1;
            int status = 0;

            if (pipe(fds) == 0 && (pid = fork()) == 0) {
                (void)close(fds[0]);
                (void)dup2(fds[1], STDOUT_FILENO);
                (void)dup2(fds[1], STDERR_FILENO);
                execv(NF_SERVER_BIN, v);
                _exit(127);
            }
            if (pid > 0) {
                size_t n = 0;

                (void)close(fds[1]);
                (void)msg[0];
                for (;;) {
                    fd_set rd;
                    struct timeval tv;
                    int r;

                    FD_ZERO(&rd);
                    FD_SET(fds[0], &rd);
                    tv.tv_sec = 0;
                    tv.tv_usec = 20000;
                    r = select(fds[0] + 1, &rd, NULL, NULL, &tv);
                    if (r > 0) {
                        ssize_t got = read(fds[0], msg + n, sizeof msg - n - 1u);

                        if (got > 0) {
                            n += (size_t)got;
                            msg[n] = '\0';
                            continue;
                        }
                    }
                    if (waitpid(pid, &status, WNOHANG) == pid) {
                        break;
                    }
                }
                (void)close(fds[0]);
                rc = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
            }
        }
        check(rc > 0,
              "--peer-tls on a node with no TLS is REFUSED at startup rather than "
              "accepted and ignored",
              msg);
        check(strstr(msg, "no TLS") != NULL,
              "the refusal says this node has no TLS, which is the thing to fix",
              msg);
        tf_tls_rmtree(dir);
        printf("== %d failure(s) ==\n", failures);
        return (failures == 0) ? 0 : 1;
    }

    /* TWO CERTIFICATES, each naming its own SERVER. The name is not decoration:
     * this node verifies a peer link's certificate against the LINK'S SERVER NAME,
     * not against the address it dialled, because 2.3 makes the name the peer's
     * identity and the address only a dial hint. A fixture whose certificates were
     * named after the host would therefore fail -- which is the correct behaviour
     * and is what makes the wrong-name case below meaningful. */
    check(tf_tls_make_cert(dir, "a", "irc.a", "DNS:irc.a,IP:127.0.0.1", 0, 86400,
                           0600) == 0,
          "generate irc.a's certificate, naming irc.a", NULL);
    check(tf_tls_make_cert(dir, "b", "irc.b", "DNS:irc.b,IP:127.0.0.1", 0, 86400,
                           0600) == 0,
          "generate irc.b's certificate, naming irc.b", NULL);

    /* ======================= CASE 1: A TLS LINK, BOTH ENDS ======================= */
    {
        static const char *const prog = "irc-serve";
        static const char *const zero = "0";
        static const char *const name_opt = "--name";
        static const char *const secret_opt = "--secret";
        static const char *const shared = "shared";
        static const char *const peer_opt = "--peer";
        static const char *const peer_tls_opt = "--peer-tls";
        static const char *const cert_opt = "--tls-cert";
        static const char *const key_opt = "--tls-key";
        static const char *const ca_opt = "--tls-ca";
        static const char *const port_opt = "--tls-port";
        argv_build_t b;

        /* B FIRST, because A's --peer has to name B's implicit-TLS PORT and B's
         * port is only knowable once B has bound it. That ordering is not a race:
         * nf_spawn_binary_argv() does not return until the child has reported the
         * port it bound, which is the same readiness handshake every other test in
         * this suite relies on. */
        ab_init(&b);
        ab_add(&b, prog);
        ab_add(&b, zero);
        ab_opt(&b, name_opt, "irc.b");
        ab_opt(&b, secret_opt, shared);
        ab_opt(&b, cert_opt, b_cert);
        ab_opt(&b, key_opt, b_key);
        ab_opt(&b, ca_opt, a_cert);
        ab_opt(&b, port_opt, zero);
        if (nf_spawn_binary_argv(&nb, ab_finish(&b)) != 0) {
            check(0, "spawn irc.b with a certificate", NULL);
            tf_tls_rmtree(dir);
            printf("== %d failure(s) ==\n", failures);
            return 1;
        }
        check(nf_expect(&nb, "tls=configured", 5000) == 0,
              "irc.b loads its certificate", NULL);
        check(nf_expect(&nb, "verify=PEER_CHAIN_AND_NAME", 5000) == 0,
              "and reports that it will verify a peer's CHAIN and its NAME -- "
              "chain verification alone accepts a certificate for a different host "
              "signed by the same authority, so both are stated",
              nb.out);

        /* A. Note the order: --peer, THEN --peer-tls. The dial hint is irc.b's
         * IMPLICIT-TLS port, so an inbound peer link from irc.b arrives where every
         * byte is already TLS; an outbound one is started by the transport on the
         * connected socket. --tls-ca is irc.b's own certificate, which is what a
         * two-node mesh of this code does: each node trusts the other's
         * certificate directly, and a real deployment would point at a CA. */
        (void)snprintf(buf, sizeof buf, "irc.b,127.0.0.1,%d", tls_port_of(&nb));
        ab_init(&b);
        ab_add(&b, prog);
        ab_add(&b, zero);
        ab_opt(&b, name_opt, "irc.a");
        ab_opt(&b, secret_opt, shared);
        ab_opt(&b, peer_opt, buf);
        ab_opt(&b, peer_tls_opt, "irc.b");
        ab_opt(&b, cert_opt, a_cert);
        ab_opt(&b, key_opt, a_key);
        ab_opt(&b, ca_opt, b_cert);
        ab_opt(&b, port_opt, zero);
        if (nf_spawn_binary_argv(&na, ab_finish(&b)) != 0) {
            check(0, "spawn irc.a with a certificate and a TLS peer", NULL);
            nf_kill(&nb);
            nf_free(&nb);
            tf_tls_rmtree(dir);
            printf("== %d failure(s) ==\n", failures);
            return 1;
        }
        check(nf_expect(&na, "link_tls: peer=irc.b require_tls=1 "
                             "enforced=outbound_dial", 5000) == 0,
              "irc.a records that the link to irc.b is REQUIRED to carry TLS, and "
              "says WHICH HALF it enforces -- the outbound dial",
              na.out);
        check(nf_expect(&na, "link_tls_start: peer=irc.b role=client", 10000) == 0,
              "irc.a starts a TLS handshake on the socket it dialled", NULL);
        check(nf_expect(&na, "link_established", 20000) == 0,
              "the link ESTABLISHES over TLS, with each side verifying the other's "
              "certificate against its --tls-ca AND the peer's server name",
              na.out);
        check(nf_expect(&nb, "link_established", 20000) == 0,
              "and the other end agrees", nb.out);

        /* THE STICKINESS, asserted by INSPECTION rather than by simulation.
         *
         * Proving it by behaviour would need a link that was TLS, went away, and
         * came back -- and the only way to make it come back in the clear would be
         * for the code to have a path that clears the flag, which is exactly what
         * the inspection rules out. So the claim is structural: `require_tls` is
         * ASSIGNED in exactly one place in link.c, that place is fed_link_set_tls(),
         * and its only caller is main() at startup. A second assignment would be a
         * downgrade path and would make this fail.
         *
         * It is a strstr rather than tf_calls() because the field is ASSIGNED rather
         * than called, and tf_calls() requires a `(` after the name. */
        {
            size_t len = 0;
            char *code = tf_read_code("src/federation/link.c", &len);
            const char *p;
            int assignments = 0;

            if (code == NULL) {
                check(0, "read src/federation/link.c", "tf_read_code failed");
            } else {
                check(strstr(code, "require_tls") != NULL,
                      "link.c consults require_tls at all", NULL);
                for (p = code; (p = strstr(p, "require_tls =")) != NULL;
                     p += 13) {
                    assignments++;
                }
                check(assignments == 1,
                      "require_tls is ASSIGNED exactly once in link.c, so there is "
                      "no path that turns a TLS link back into a plaintext one",
                      "a second assignment to require_tls is a downgrade path");
                free(code);
            }
            code = tf_read_code("src/node_main.c", &len);
            if (code != NULL) {
                check(tf_calls(code, "fed_link_set_tls") == 1,
                      "and its only caller is main(), which calls it once per "
                      "--peer-tls before the loop can dial anything",
                      NULL);
                free(code);
            } else {
                check(0, "read src/node_main.c", "tf_read_code failed");
            }
        }

        (void)nf_stop(&na);
        check(nf_expect_u64(&na, "tls_handshake_failed=", 0u, 5000) == 0,
              "no peer-link handshake failed, for two nodes whose certificates "
              "verify against each other's --tls-ca and name each other",
              NULL);
        nf_free(&na);
        (void)nf_stop(&nb);
        nf_free(&nb);
    }

    /* ============ CASE 2: A PEER WHOSE CERTIFICATE DOES NOT VERIFY ============ */
    {
        static const char *const prog = "irc-serve";
        static const char *const zero = "0";
        static const char *const name_opt = "--name";
        static const char *const secret_opt = "--secret";
        static const char *const shared = "shared";
        static const char *const peer_opt = "--peer";
        static const char *const peer_tls_opt = "--peer-tls";
        static const char *const cert_opt = "--tls-cert";
        static const char *const key_opt = "--tls-key";
        static const char *const ca_opt = "--tls-ca";
        static const char *const port_opt = "--tls-port";
        argv_build_t b;

        ab_init(&b);
        ab_add(&b, prog);
        ab_add(&b, zero);
        ab_opt(&b, name_opt, "irc.b");
        ab_opt(&b, secret_opt, shared);
        ab_opt(&b, cert_opt, b_cert);
        ab_opt(&b, key_opt, b_key);
        ab_opt(&b, port_opt, zero);
        if (nf_spawn_binary_argv(&nb, ab_finish(&b)) != 0) {
            check(0, "spawn irc.b for the unverified-peer case", NULL);
        } else {
            /* A THIRD, UNRELATED authority for irc.a to trust. It shares no key and
             * no name with either node's certificate, so there is no chain from
             * irc.b's certificate to this anchor AT ALL -- which is the case that
             * proves the verification is real rather than a flag that is set and not
             * read. A mismatch in one field would be a weaker test: it could be
             * satisfied by a name check alone. */
            (void)tf_tls_make_cert(dir, "wrongca", "someone.else",
                                   "IP:127.0.0.1", 0, 86400, 0600);
            (void)snprintf(a_tls, sizeof a_tls, "%s/wrongca.crt", dir);
            (void)snprintf(buf, sizeof buf, "irc.b,127.0.0.1,%d",
                           tls_port_of(&nb));

            ab_init(&b);
            ab_add(&b, prog);
            ab_add(&b, zero);
            ab_opt(&b, name_opt, "irc.a");
            ab_opt(&b, secret_opt, shared);
            ab_opt(&b, peer_opt, buf);
            ab_opt(&b, peer_tls_opt, "irc.b");
            ab_opt(&b, cert_opt, a_cert);
            ab_opt(&b, key_opt, a_key);
            ab_opt(&b, ca_opt, a_tls);
            ab_opt(&b, port_opt, zero);
            if (nf_spawn_binary_argv(&na, ab_finish(&b)) != 0) {
                check(0, "spawn irc.a with the WRONG trust anchor", NULL);
            } else {
                check(nf_expect(&na, "link_tls_start: peer=irc.b", 15000) == 0,
                      "irc.a starts the handshake", NULL);
                check(nf_expect(&na, "link_established", 8000) != 0,
                      "and the link NEVER ESTABLISHES: a peer whose certificate does "
                      "not verify against --tls-ca is refused rather than accepted "
                      "in the clear, which is the whole point of configuring one",
                      na.out);
                (void)nf_stop(&na);
                check(nf_expect_u64(&na, "fed_dead=", 0u, 5000) == 0,
                      "and irc.a never counted a link DEAD, because the link never "
                      "reached ESTABLISHED in the first place", NULL);
                /* THE TCP CONNECT SUCCEEDED AND THE TLS HANDSHAKE DID NOT, and
                 * saying so precisely is the point: `dial_connected` is 1 and
                 * `dial_failed` is 0, so the failure is unambiguously at the
                 * certificate and not at the socket. A test that asserted
                 * `dial_failed >= 1` would have been asserting something false
                 * about the code and would have had to be weakened into
                 * meaninglessness to pass. */
                check(nf_expect_u64(&na, "dial_connected=", 1u, 5000) == 0,
                      "the TCP connection to the peer SUCCEEDED: the failure is at "
                      "the certificate and not at the socket", NULL);
                check(nf_expect_u64(&na, "dial_failed=", 0u, 5000) == 0,
                      "and no dial failed at the socket layer", NULL);
                check(nf_expect(&na, "tls_error", 5000) == 0,
                      "and OpenSSL's reason is on the wire, so an operator can tell "
                      "a certificate problem from a network one", NULL);
                nf_free(&na);
            }
            (void)nf_stop(&nb);
            nf_free(&nb);
        }
    }

    /* ============== CASE 3: THE MIXED MESH IS PERMITTED ============== */
    {
        static const char *const prog = "irc-serve";
        static const char *const zero = "0";
        static const char *const name_opt = "--name";
        static const char *const secret_opt = "--secret";
        static const char *const shared = "shared";
        static const char *const peer_opt = "--peer";
        static const char *const cert_opt = "--tls-cert";
        static const char *const key_opt = "--tls-key";
        static const char *const port_opt = "--tls-port";
        argv_build_t b;

        /* A NODE WITH TLS AND A PEER THAT HAS NONE, AND THE LINK WORKS.
         *
         * This is the decision's permissive half and it is the half an
         * implementation would break by refusing to dial anything once --tls-cert
         * was given. The cost of that mistake is the coordinated cutover the mixing
         * exists to avoid: no deployment could adopt TLS until EVERY peer was ready,
         * so no deployment would adopt it.
         *
         * The peer has no certificate, so this link cannot be anything but
         * plaintext, and it ESTABLISHES. The assertions around the claim are what
         * make it specific rather than "something happened": irc.a reports that it
         * started NO handshake for this link, and the peer reports that it
         * established one -- so the link that worked is the plaintext one and not a
         * TLS link to something else. */
        ab_init(&b);
        ab_add(&b, prog);
        ab_add(&b, zero);
        ab_opt(&b, name_opt, "irc.b");
        ab_opt(&b, secret_opt, shared);
        if (nf_spawn_binary_argv(&nb, ab_finish(&b)) != 0) {
            check(0, "spawn a PLAINTEXT peer for the mixed-mesh case", NULL);
        } else {
            (void)snprintf(buf, sizeof buf, "irc.b,127.0.0.1,%d", nb.port);

            ab_init(&b);
            ab_add(&b, prog);
            ab_add(&b, zero);
            ab_opt(&b, name_opt, "irc.a");
            ab_opt(&b, secret_opt, shared);
            ab_opt(&b, peer_opt, buf);
            ab_opt(&b, cert_opt, a_cert);
            ab_opt(&b, key_opt, a_key);
            ab_opt(&b, port_opt, zero);
            if (nf_spawn_binary_argv(&na, ab_finish(&b)) != 0) {
                check(0, "spawn a TLS-configured node for the mixed-mesh case", NULL);
            } else {
                check(nf_expect(&na, "link_dial: peer=irc.b", 10000) == 0,
                      "a node configured with TLS DIALS a peer that has none", NULL);
                check(nf_expect(&na, "link_tls_start:", 4000) != 0,
                      "and starts NO TLS handshake for that link: require_tls is a "
                      "property of the LINK and not of the node, so configuring TLS "
                      "does not silently make every link encrypted",
                      na.out);
                check(nf_expect(&na, "link_established", 20000) == 0,
                      "and the PLAINTEXT link establishes normally -- the mixed "
                      "mesh is SUPPORTED rather than merely tolerated",
                      na.out);
                check(nf_expect(&nb, "link_established", 20000) == 0,
                      "and the peer without a certificate agrees", nb.out);
                (void)nf_stop(&na);
                check(nf_expect_u64(&na, "tls_handshake_failed=", 0u, 5000) == 0,
                      "no TLS handshake was attempted for the plaintext link, so "
                      "nothing TLS-related failed on it",
                      NULL);
                nf_free(&na);
            }
            (void)nf_stop(&nb);
            nf_free(&nb);
        }
    }

    /* ============== CASE 4: A PEER WHOSE NAME STARTS WITH A DIGIT ============
     *
     * WHY THIS CASE EXISTS AT ALL, and it is a security case that happens to have
     * a passing half, so the two halves are asserted TOGETHER and neither is
     * allowed to stand alone:
     *
     * tls_openssl.c decided whether a peer name was an IP address or a hostname by
     * reading its FIRST CHARACTER. A 2.4 server name may start with a digit --
     * node_main.c's --name says "must start with a letter or digit" and
     * irc_serve_server_name_valid() enforces exactly that -- so `1peer`, a name
     * this project accepts everywhere, was sent to X509_VERIFY_PARAM_set1_ip_asc(),
     * was refused by it, and LEFT THE VERIFY PARAMETER WITH NO NAME IN IT. A
     * handshake with no expected name verifies the CHAIN and nothing else, so peer
     * authentication on such a link degraded to "signed by somebody in my mesh CA".
     * Demonstrated end to end against the shipped binary: node B `--name 1peer`
     * presenting a CA-issued certificate for `DNS:someone.else`, node A with
     * `--peer 1peer --peer-tls 1peer --tls-ca ca.crt`, and the log said
     * `link_established: peer=1peer`.
     *
     * THE CONSEQUENCE, and it is what makes this HIGH rather than MEDIUM: the
     * federation secret is MESH-WIDE. So any node holding any CA-issued
     * certificate plus that one shared secret could impersonate any digit-named
     * peer -- read the message stream, inject into it, and be introduced to third
     * parties as a node this mesh believes is somebody else.
     *
     * TWO HALVES, AND THE SECOND IS NOT OPTIONAL. A fix that reads "refuse any
     * peer name starting with a digit" passes the security assertion below and
     * breaks every mesh that has one, which is why the MATCHING case is here and
     * why it asserts an ESTABLISHMENT rather than an absence: `1peer` is a legal
     * name and a legal DNS label, it must keep working, and the certificate it
     * presents has to be verified against it.
     */
    {
        static const char *const prog = "irc-serve";
        static const char *const zero = "0";
        static const char *const name_opt = "--name";
        static const char *const secret_opt = "--secret";
        static const char *const shared = "shared";
        static const char *const peer_opt = "--peer";
        static const char *const peer_tls_opt = "--peer-tls";
        static const char *const cert_opt = "--tls-cert";
        static const char *const key_opt = "--tls-key";
        static const char *const ca_opt = "--tls-ca";
        static const char *const port_opt = "--tls-port";
        argv_build_t b;

        /* THE SAN NAMES `1peer`. This is the certificate whose name is WRONG for
         * CASE 5 and right for CASE 4, and the whole pair turns on that one
         * field: both cases trust this exact file as --tls-ca and B presents this
         * exact file, so the CHAIN verifies identically in each. */
        check(tf_tls_make_cert(dir, "digit", "1peer", "DNS:1peer,IP:127.0.0.1", 0,
                               86400, 0600) == 0,
              "generate a certificate whose SAN is DNS:1peer -- a name starting "
              "with a DIGIT, which node_main.c's --name grammar accepts",
              NULL);
        (void)snprintf(digit_crt, sizeof digit_crt, "%s/digit.crt", dir);
        (void)snprintf(digit_key, sizeof digit_key, "%s/digit.key", dir);

        ab_init(&b);
        ab_add(&b, prog);
        ab_add(&b, zero);
        ab_opt(&b, name_opt, "1peer");
        ab_opt(&b, secret_opt, shared);
        ab_opt(&b, cert_opt, digit_crt);
        ab_opt(&b, key_opt, digit_key);
        ab_opt(&b, ca_opt, a_cert);
        ab_opt(&b, port_opt, zero);
        if (nf_spawn_binary_argv(&nb, ab_finish(&b)) != 0) {
            check(0, "spawn a peer named 1peer", NULL);
        } else {
            (void)snprintf(buf, sizeof buf, "1peer,127.0.0.1,%d",
                           tls_port_of(&nb));
            ab_init(&b);
            ab_add(&b, prog);
            ab_add(&b, zero);
            ab_opt(&b, name_opt, "irc.a");
            ab_opt(&b, secret_opt, shared);
            ab_opt(&b, peer_opt, buf);
            ab_opt(&b, peer_tls_opt, "1peer");
            ab_opt(&b, cert_opt, a_cert);
            ab_opt(&b, key_opt, a_key);
            ab_opt(&b, ca_opt, digit_crt);
            ab_opt(&b, port_opt, zero);
            if (nf_spawn_binary_argv(&na, ab_finish(&b)) != 0) {
                check(0, "spawn irc.a against the digit-named peer", NULL);
            } else {
                check(nf_expect(&na, "link_tls_start: peer=1peer role=client",
                                15000) == 0,
                      "irc.a starts a TLS handshake for the DIGIT-named peer", NULL);
                /* THE ASSERTION THAT A REFUSE-EVERY-DIGIT FIX FAILS. `1peer` is a
                 * legal server name and its certificate's SAN matches it, so the
                 * name check has something to check and must PASS. */
                check(nf_expect(&na, "link_established: peer=1peer", 20000) == 0,
                      "and the link ESTABLISHES: a peer whose name starts with a "
                      "digit is a legal name, and fixing the skipped name check "
                      "must not turn into refusing digit-named peers",
                      na.out);
                (void)nf_stop(&na);
                check(nf_expect_u64(&na, "tls_handshake_failed=", 0u, 5000) == 0,
                      "no handshake failed for it, because its certificate names "
                      "it and this node verified that",
                      NULL);
                nf_free(&na);
            }
            (void)nf_stop(&nb);
            nf_free(&nb);
        }
    }

    /* ==== CASE 5: THE SAME DIGIT-NAMED PEER, PRESENTING A WRONG-NAME CERT ==== */
    {
        static const char *const prog = "irc-serve";
        static const char *const zero = "0";
        static const char *const name_opt = "--name";
        static const char *const secret_opt = "--secret";
        static const char *const shared = "shared";
        static const char *const peer_opt = "--peer";
        static const char *const peer_tls_opt = "--peer-tls";
        static const char *const cert_opt = "--tls-cert";
        static const char *const key_opt = "--tls-key";
        static const char *const ca_opt = "--tls-ca";
        static const char *const port_opt = "--tls-port";
        argv_build_t b;
        int b_tls_port;

        /* A CERTIFICATE FOR A DIFFERENT NAME, TRUSTED. The chain verifies -- this
         * file is what irc.a is given as --tls-ca, and B presents the same file, so
         * the ONLY thing wrong with it is the name. That is what makes this case
         * the name check's case rather than a re-run of CASE 2's untrusted-CA
         * case: here a certificate that merely CHAINS is not enough. */
        check(tf_tls_make_cert(dir, "wrongname", "someone.else",
                               "DNS:someone.else", 0, 86400, 0600) == 0,
              "generate a CA-issued certificate naming DNS:someone.else, which is "
              "NOT the name of any peer in this test",
              NULL);
        (void)snprintf(wrong_crt, sizeof wrong_crt, "%s/wrongname.crt", dir);
        (void)snprintf(wrong_key, sizeof wrong_key, "%s/wrongname.key", dir);

        ab_init(&b);
        ab_add(&b, prog);
        ab_add(&b, zero);
        ab_opt(&b, name_opt, "1peer");
        ab_opt(&b, secret_opt, shared);
        ab_opt(&b, cert_opt, wrong_crt);
        ab_opt(&b, key_opt, wrong_key);
        ab_opt(&b, ca_opt, a_cert);
        ab_opt(&b, port_opt, zero);
        if (nf_spawn_binary_argv(&nb, ab_finish(&b)) != 0) {
            check(0, "spawn 1peer presenting a certificate for someone.else", NULL);
        } else {
            b_tls_port = tls_port_of(&nb);

            /* ---- 5a: THE ATTACK. The peer is named `1peer` and presents a
             * certificate for `someone.else`. ---- */
            (void)snprintf(buf, sizeof buf, "1peer,127.0.0.1,%d", b_tls_port);
            ab_init(&b);
            ab_add(&b, prog);
            ab_add(&b, zero);
            ab_opt(&b, name_opt, "irc.a");
            ab_opt(&b, secret_opt, shared);
            ab_opt(&b, peer_opt, buf);
            ab_opt(&b, peer_tls_opt, "1peer");
            ab_opt(&b, cert_opt, a_cert);
            ab_opt(&b, key_opt, a_key);
            ab_opt(&b, ca_opt, wrong_crt);
            ab_opt(&b, port_opt, zero);
            if (nf_spawn_binary_argv(&na, ab_finish(&b)) != 0) {
                check(0, "spawn irc.a against it", NULL);
            } else {
                check(nf_expect(&na, "link_tls_start: peer=1peer", 15000) == 0,
                      "irc.a starts the handshake, so the certificate is checked "
                      "rather than the link being abandoned before the check -- "
                      "which is what makes the refusal below a NAME refusal",
                      NULL);
                /* THE ASSERTION THE SKIPPED NAME CHECK FAILS. Reverted to the
                 * first-character discriminator this printed
                 * `link_established: peer=1peer`, and the whole mesh's federation
                 * secret rides on it. */
                check(nf_expect(&na, "link_established: peer=1peer", 8000) != 0,
                      "and the link NEVER ESTABLISHES: a peer name starting with a "
                      "digit is verified against the peer's NAME like any other, "
                      "so a certificate for someone.else is refused even though it "
                      "chains to the configured --tls-ca",
                      na.out);
                check(nf_expect(&na, "tls_error", 5000) == 0,
                      "OpenSSL's reason is on the wire, so an operator can tell "
                      "this from a socket fault or an untrusted chain", NULL);
                (void)nf_stop(&na);
                nf_free(&na);
            }

            /* ---- 5b: THE CONTROL, and it is why 5a means anything.
             *
             * The SAME certificate, the SAME trust anchor, the SAME peer socket --
             * dialled under a LETTER-initial peer name. Nothing about the
             * certificate or the store changes; only the name does. So the two
             * runs together say that the name is what decides, and 5a's refusal
             * cannot be an artefact of this build refusing something else.
             *
             * It also pins the behaviour the fix had to MATCH rather than invent:
             * a letter-named peer with a wrong-name certificate was already
             * refused before this fix, and a fix that made the digit case behave
             * differently would have made the mesh's security depend on the first
             * character of a name. */
            (void)snprintf(buf, sizeof buf, "irc.b,127.0.0.1,%d", b_tls_port);
            ab_init(&b);
            ab_add(&b, prog);
            ab_add(&b, zero);
            ab_opt(&b, name_opt, "irc.a");
            ab_opt(&b, secret_opt, shared);
            ab_opt(&b, peer_opt, buf);
            ab_opt(&b, peer_tls_opt, "irc.b");
            ab_opt(&b, cert_opt, a_cert);
            ab_opt(&b, key_opt, a_key);
            ab_opt(&b, ca_opt, wrong_crt);
            ab_opt(&b, port_opt, zero);
            if (nf_spawn_binary_argv(&na, ab_finish(&b)) != 0) {
                check(0, "spawn irc.a for the letter-named control", NULL);
            } else {
                check(nf_expect(&na, "link_established: peer=irc.b", 8000) != 0,
                      "the CONTROL: the identical certificate dialled under the "
                      "letter-named peer `irc.b` is refused too, so the digit case "
                      "now answers exactly as the letter case always did",
                      na.out);
                /* nf_stop() BEFORE nf_free(), as every other case here does, and
                 * the reason is worth recording because it cost a 180-second ctest
                 * timeout once: nf_free() closes the harness's pipe but does not
                 * kill the child, and an orphaned node still holds the WRITE end of
                 * the pipe ctest is reading this test's output through. Under a
                 * shell redirect that is invisible; under ctest the run does not
                 * reach EOF until the orphan dies, so the suite times out on a test
                 * that printed its last line seconds earlier. */
                (void)nf_stop(&na);
                nf_free(&na);
            }
            (void)nf_stop(&nb);
            nf_free(&nb);
        }
    }

    tf_tls_rmtree(dir);
    printf("== %d failure(s) ==\n", failures);
    return (failures == 0) ? 0 : 1;
}
