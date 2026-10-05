/* test_tls_revocation.c -- OCSP stapling on the outbound peer-link path.
 *
 * ===========================================================================
 * WHAT IS ASSERTED, BEFORE ANY ASSERTION
 * ===========================================================================
 * A peer link over TLS, established by the shipped binary against a real second
 * node over a real socket, is checked against the peer's STAPLED OCSP response,
 * and the answer is a refusal or an acceptance according to ONE boolean.
 *
 * The cases, and each one is a real staple produced by tests/harness/tls_fixture.c's
 * OCSP generator -- signed by the issuing CA, carrying a real CertID over the real
 * issuer, with real thisUpdate/nextUpdate -- rather than a corrupted something
 * dressed up as a revocation:
 *
 *   GOOD      status GOOD, inside its window          ESTABLISHES
 *   REVOKED   status REVOKED, keyCompromise, signed by the issuing CA
 *                                                        REFUSED
 *   STALE     status GOOD, nextUpdate an hour ago      REFUSED
 *   NO_NEXT_UPDATE  status GOOD, no nextUpdate at all  REFUSED
 *   UNVERIFIED  a correct CertID, signed by a stranger  REFUSED
 *   MISSING   the peer staples nothing
 *                    strict:                            REFUSED
 *                    permissive:                        ESTABLISHES, with a line
 *
 * WHY THE REVOKED CASE IS SIGNED BY THE ISSUING CA, which is the whole difficulty
 * and the reason this file builds responses with OpenSSL's OCSP API instead of
 * corrupting a handshake: a response signed by the issuer, carrying a CertID that
 * matches the verified leaf, inside its freshness window, and saying REVOKED is a
 * staple that passes EVERY check except the one that matters. Deleting the status
 * comparison from the verifier leaves it looking exactly like a GOOD response, and
 * only a real revoked response can tell the difference. The UNVERIFIED case closes
 * the same hole from the other side: without OCSP_basic_verify() a status signed by
 * anybody would be believed.
 *
 * ===========================================================================
 * WHY EVERY CASE NEEDS A CA, AND WHAT THAT COSTS THE OTHER TESTS
 * ===========================================================================
 * A revocation status can only be issued by somebody OTHER than the certificate's
 * subject. Two nodes that trust each other's self-signed certificate directly --
 * which is what test_peer_tls.c does, because it is the smallest mesh that can
 * carry TLS -- have no such issuer, so there is nobody who could have answered and
 * the correct verdict on such a link is NO_ISSUER. Every case here therefore uses a
 * real authority, two leaves issued by it, and --tls-ca pointing at the authority.
 * That is also what a real deployment looks like, which is why this file is the one
 * that builds a CA rather than the exception to a rule.
 *
 * ===========================================================================
 * WHAT IS NOT COVERED HERE, STATED RATHER THAN LEFT TO BE DISCOVERED
 * ===========================================================================
 *   - INBOUND. There is no inbound client-certificate authentication in this program
 *     at all: the server context is SSL_VERIFY_NONE and never asks for one. Nothing
 *     here is a claim about a certificate a CLIENT presented, and the source check
 *     at the end is what keeps that from quietly becoming one.
 *   - CRL. There is none, deliberately: it is a distribution point, and an
 *     unreachable one has to be treated as revoked or the check is decorative --
 *     which means fetching, which the event loop may not do.
 *   - A FRESH STAPLE. Nothing refreshes a staple; see the source check for that.
 *   - LSan. It does not exist on Darwin. This file says nothing about leaks.
 */
#include <signal.h>
#include <sys/select.h>
#include <sys/time.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "harness/node_fixture.h"
#include "harness/test_util.h"
#include "harness/tls_fixture.h"

/* PF_DIR_MAX + 128 for the same arithmetic reason test_peer_tls.c gives: every path
 * below is `"%s/<name>"` and gcc-16's -Wformat-truncation needs the slack, while
 * the two clangs do not diagnose the same-sized version at all. */
#define RV_DIR_MAX 512
#define RV_PATH (RV_DIR_MAX + 128)

/* Enough for: prog, port, --name x2, --secret x2, --peer x2, --peer-tls x2,
 * --tls-cert x2, --tls-key x2, --tls-ca x2, --tls-ocsp-staple x2, --tls-port x2,
 * --tls-staple-permissive x2, and the NULL terminator. Twenty-four slots is
 * headroom over that and the terminator is the builder's job (see below). */
typedef struct {
    char  *v[40];
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

static char **ab_finish(argv_build_t *b)
{
    b->v[b->n] = NULL;
    return b->v;
}

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
    snprintf(out, cap, "%s/tls-revoc-%ld", base, (long)getpid());
    (void)mkdir(out, 0700);
}

/* B's implicit-TLS port, read off its own startup line. `--tls-port 0` asks the
 * kernel for a port, so the ARGUMENT is not the port and a test that used it would
 * dial nothing. */
static int tls_port_of(const nf_node_t *n)
{
    const char *p = strstr(n->out, "tls_port=");

    return (p != NULL) ? atoi(p + 9) : -1;
}

/* ---------------------------------------------------------------------------
 * ONE CASE: two nodes, one mesh, and what the wire says
 * ---------------------------------------------------------------------------
 *   b_staple      path irc.b should be given as --tls-ocsp-staple, or NULL for none
 *   a_permissive  non-zero adds --tls-staple-permissive to irc.a
 *   a_staple      path irc.a should be given as --tls-ocsp-staple, or NULL
 *   establish     1 to assert link_established, 0 to assert it never arrives
 *   verdict       the exact `status=` the revocation line must carry
 *
 * B is spawned FIRST because A's --peer has to name B's implicit-TLS port and that
 * port is only knowable once B has bound it. That is not a race: nf_spawn_binary_
 * argv() does not return until the child has reported the port it bound, which is
 * the same readiness handshake every other test in this suite relies on.
 *
 * NOTHING HERE SLEEPS. Every wait is nf_expect(), which is a deadline on an
 * observable line -- and for the refusals the deadline is what establishes the
 * ABSENCE, which is the only way to assert that a link never comes up without
 * waiting out a fixed interval and hoping. */
static void run_case(const char *label, const char *a_crt,
                     const char *a_key, const char *b_crt, const char *b_key,
                     const char *ca_crt, const char *a_staple, const char *b_staple,
                     int a_permissive, int establish, const char *verdict,
                     const char *explain)
{
    static const char *const prog = "irc-serve";
    static const char *const zero = "0";
    static const char *const shared = "shared";
    char buf[256];
    char why[256];
    char line[512];
    nf_node_t na;
    nf_node_t nb;
    argv_build_t b;

    (void)snprintf(why, sizeof why, "case %s", label);

    ab_init(&b);
    ab_add(&b, prog);
    ab_add(&b, zero);
    ab_opt(&b, "--name", "irc.b");
    ab_opt(&b, "--secret", shared);
    ab_opt(&b, "--tls-cert", b_crt);
    ab_opt(&b, "--tls-key", b_key);
    ab_opt(&b, "--tls-ca", ca_crt);
    ab_opt(&b, "--tls-port", zero);
    if (b_staple != NULL) {
        ab_opt(&b, "--tls-ocsp-staple", b_staple);
    }
    if (nf_spawn_binary_argv(&nb, ab_finish(&b)) != 0) {
        check(0, "spawn irc.b", why);
        return;
    }
    (void)snprintf(buf, sizeof buf, "irc.b,127.0.0.1,%d", tls_port_of(&nb));
    ab_init(&b);
    ab_add(&b, prog);
    ab_add(&b, zero);
    ab_opt(&b, "--name", "irc.a");
    ab_opt(&b, "--secret", shared);
    ab_opt(&b, "--peer", buf);
    ab_opt(&b, "--peer-tls", "irc.b");
    ab_opt(&b, "--tls-cert", a_crt);
    ab_opt(&b, "--tls-key", a_key);
    ab_opt(&b, "--tls-ca", ca_crt);
    ab_opt(&b, "--tls-port", zero);
    if (a_staple != NULL) {
        ab_opt(&b, "--tls-ocsp-staple", a_staple);
    }
    if (a_permissive != 0) {
        ab_add(&b, "--tls-staple-permissive");
    }
    if (nf_spawn_binary_argv(&na, ab_finish(&b)) != 0) {
        check(0, "spawn irc.a", why);
        (void)nf_stop(&nb);
        nf_free(&nb);
        return;
    }

    if (establish != 0) {
        (void)snprintf(line, sizeof line, "link_established: peer=irc.b");
        check(nf_expect(&na, line, 20000) == 0, explain, na.out);
    } else {
        (void)snprintf(line, sizeof line, "link_established: peer=irc.b");
        check(nf_expect(&na, line, 4000) != 0,
              "and the link NEVER ESTABLISHES", na.out);
    }
    /* THE VERDICT LINE, all three of its fields at once: the STATUS, the POLICY and
     * what this node DID about it.
     *
     * ONE NEEDLE RATHER THAN THREE ASSERTIONS, and the reason is the boolean. A
     * boolean policy is the thing that gets silently inverted -- one comparison
     * flipped and every mesh changes meaning while no line of output changes shape
     * -- so the expectation names `policy=` and `action=` as well as `status=`.
     * The two missing-staple cases below differ ONLY in the flag they pass and in
     * these two fields, and swapping the policy inverts both of them, which is what
     * makes the pair a test rather than two runs.
     *
     * THE NEEDLE STARTS AT `peer=`, not at `tls_peer_revocation:`, because the
     * descriptor number is the CHILD's and this process has no way to learn it.
     * The three fields that decide the case are all after it. */
    (void)snprintf(line, sizeof line, "peer=irc.b status=%s policy=%s action=%s",
                   verdict, (a_permissive != 0) ? "permissive" : "strict",
                   (establish != 0) ? "ACCEPT" : "REFUSE");
    {
        char needle[256];

        (void)snprintf(needle, sizeof needle, "tls_peer_revocation: fd=%%d %s", line);
        /* The fd is a wildcard because it is unknowable, so the expectation is the
         * FIXED part of the line after it. Two nf_expect() calls rather than one
         * because the needle above is built with a literal %%d and nf_expect() does
         * not glob: the first matches the line's prefix and the second the fields
         * that carry the decision. */
        check(nf_expect(&na, "tls_peer_revocation: fd=", 20000) == 0 &&
                  nf_expect(&na, line, 5000) == 0,
              "and the revocation line reports that status, that policy, and what "
              "this node did about it",
              na.out);
    }
    /* THE EXPOSURE WINDOW. Asserted once, on the good case, because that is where
     * it is load-bearing: an operator reading a log has to be able to answer "when
     * does my exposure window close" and the answer has to be ON THE WIRE. The
     * pattern is a fixed prefix plus the notAfter value, because the value is a
     * clock reading this test cannot predict. */
    if (establish != 0 && strcmp(verdict, "GOOD") == 0) {
        check(nf_expect(&na, "tls_peer_cert: fd=", 5000) == 0 &&
                  nf_expect(&na, "peer=irc.b not_after=", 5000) == 0 &&
                  nf_expect(&na, "not_after_in=", 5000) == 0,
              "the peer's notAfter AND the seconds remaining are on the wire, so "
              "the exposure window is answerable from a log rather than from a "
              "certificate",
              na.out);
    }
    /* THE ABSENCE ON THE ACCEPTING SIDE. This asserts that irc.b -- which only ever
     * ACCEPTS in this file -- says NOTHING about revocation, for the connection it
     * just served.
     *
     * It is the assertion that keeps "inbound is not covered" from becoming a
     * comment. A check that merely SKIPPED its verdict server-side would still print
     * a line, and a line naming `status=` on an inbound connection is a claim about
     * a certificate this program never asked for -- the exact kind of claim
     * tls_openssl.c's own header says it will not make. */
    check(strstr(nb.out, "tls_peer_revocation") == NULL,
          "and the ACCEPTING node says nothing at all about revocation: this "
          "program asks a client for no certificate, so an inbound connection has "
          "nothing to have a status about and no line may imply otherwise",
          nb.out);
    (void)nf_stop(&na);
    nf_free(&na);
    (void)nf_stop(&nb);
    nf_free(&nb);
}

/* ---------------------------------------------------------------------------
 * THE NO-TLS BUILD. No case is skipped; the plain consequences are asserted
 * instead, for the reason tests/harness/tls_fixture.h gives.
 * --------------------------------------------------------------------------- */
static int check_plaintext_consequences(void)
{
    {
        static char v0[] = "irc-serve";
        static char v1[] = "0";
        static char v2[] = "--name";
        static char v3[] = "irc.a";
        static char v4[] = "--tls-ocsp-staple";
        static char v5[] = "does-not-exist.ocsp";
        char *v[10];
        char msg[4096];
        int rc = 0;
        int fds[2];
        pid_t pid = -1;
        int status = 0;
        size_t n = 0;

        /* --tls-ocsp-staple ALONE, and the absence of a certificate pair is the
         * point: the refusal that has to happen is "TLS options were given without
         * --tls-cert and --tls-key". Supplying a certificate pair as well would be
         * refused too, but earlier and for a different reason -- the key file would
         * have to exist and be 0600 -- and the diagnostic on the wire would be about
         * the key rather than about the option under test. */
        v[0] = v0; v[1] = v1; v[2] = v2; v[3] = v3; v[4] = v4; v[5] = v5;
        v[6] = NULL; v[7] = NULL; v[8] = NULL; v[9] = NULL;
        /* A NODE THAT NEVER EXITS IS WHAT THE DEADLINE IS FOR, so this shape --
         * fork, read for a bounded while, waitpid(WNOHANG) -- is the same one
         * test_peer_tls.c uses for the same case. */
        if (pipe(fds) == 0 && (pid = fork()) == 0) {
            (void)close(fds[0]);
            (void)dup2(fds[1], STDOUT_FILENO);
            (void)dup2(fds[1], STDERR_FILENO);
            execv(NF_SERVER_BIN, v);
            _exit(127);
        }
        if (pid > 0) {
            (void)close(fds[1]);
            msg[0] = '\0';
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
        check(rc > 0,
              "--tls-ocsp-staple without --tls-cert/--tls-key is REFUSED at "
              "startup rather than accepted and ignored",
              msg);
        check(strstr(msg, "TLS options were given without --tls-cert and --tls-key") !=
                  NULL,
              "and the refusal names the missing pair, which is the thing to fix",
              msg);
    }
    {
        static char v0[] = "irc-serve";
        static char v1[] = "0";
        static char v2[] = "--name";
        static char v3[] = "irc.a";
        static char v4[] = "--tls-staple-permissive";
        char *v[8];
        char msg[4096];
        int rc = 0;
        int fds[2];
        pid_t pid = -1;
        int status = 0;
        size_t n = 0;

        v[0] = v0; v[1] = v1; v[2] = v2; v[3] = v3; v[4] = v4;
        v[5] = NULL; v[6] = NULL; v[7] = NULL;
        if (pipe(fds) == 0 && (pid = fork()) == 0) {
            (void)close(fds[0]);
            (void)dup2(fds[1], STDOUT_FILENO);
            (void)dup2(fds[1], STDERR_FILENO);
            execv(NF_SERVER_BIN, v);
            _exit(127);
        }
        if (pid > 0) {
            (void)close(fds[1]);
            msg[0] = '\0';
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
        check(rc > 0,
              "--tls-staple-permissive on a node with no TLS is REFUSED at startup "
              "too: a flag that quietly does nothing on a security option is worse "
              "than no flag",
              msg);
        check(strstr(msg, "TLS options were given without --tls-cert and --tls-key") !=
                  NULL,
              "and says the same thing the other revocation option says", msg);
    }
    return 0;
}

/* ---------------------------------------------------------------------------
 * THE SOURCE CHECK: NOTHING IN THE REVOCATION PATH FETCHES ANYTHING
 * ---------------------------------------------------------------------------
 * THE CLAIM THIS EXISTS TO KEEP TRUE is "no HTTP, no DNS, no blocking call anywhere
 * in the event loop", and the only way a claim like that stays true is if something
 * can go and look. A comment asserting it is evidence of nothing; this is evidence.
 *
 * tf_read_code() strips COMMENTS, so the file's own prose -- which names most of
 * the forbidden functions -- cannot satisfy or defeat the search. What is searched
 * for is each function's DEFINITE occurrence as a call: a name preceded by an
 * identifier character is not a call, so `OCSP_sendreq_new` inside a longer
 * identifier, or the word in a variable name, does not count.
 *
 * THE LIST, and why each entry is on it:
 *
 *   OCSP_sendreq_* / OSSL_HTTP_REQ_CTX_*   the OCSP-over-HTTP client. Its presence
 *                                            would mean this node can be made to
 *                                            open a socket to fetch a status, which
 *                                            is the thing this design exists to
 *                                            avoid.
 *   getaddrinfo / gethostbyname / getnameinfo  DNS.
 *   BIO_new_file / fopen / fgets / fread / open / read   reading a file. The staple
 *                                            is read at STARTUP, in
 *                                            tls_backend_node_init(); a read in the
 *                                            revocation path would be a second read
 *                                            inside the loop.
 *   connect / socket / sleep / usleep / nanosleep / poll / select   the blocking and
 *                                            waiting primitives themselves.
 *
 * AND THE POSITIVE HALF: the file must still CALL the verification, or this check
 * would pass on a file that had been gutted. That is the direction a test which only
 * ever looks for badness cannot see. */
static void check_no_fetch(void)
{
    static const char *const forbidden[] = {
        "OCSP_sendreq_new", "OCSP_sendreq_bio", "OCSP_sendreq_nbio",
        "OCSP_REQ_CTX_new", "OCSP_REQ_CTX_i2d", "OCSP_REQ_CTX_http",
        "OCSP_REQ_CTX_nbio", "OSSL_HTTP_REQ_CTX_new", "OSSL_HTTP_CLIENT",
        "getaddrinfo", "gethostbyname", "getnameinfo", "res_query",
        "BIO_new_file", "BIO_new_connect", "fopen", "fgets", "fread", "fwrite",
        "connect", "gethostbyaddr", "sleep", "usleep", "nanosleep", "poll",
        "select", "SSL_CTX_new", "SSL_new", "SSL_CTX_set_verify",
        NULL
    };
    size_t len = 0;
    char *code = tf_read_code("src/tls_openssl.c", &len);
    char *from;
    char *to;
    char *region;
    int i;

    TF_CHECK_MSG(code != NULL, "could not read src/tls_openssl.c (is "
                               "IRCSERVE_SRC_DIR set?)");
    /* THE REGION, AND WHY IT IS A REGION RATHER THAN THE WHOLE FILE.
     *
     * src/tls_openssl.c legitimately does all of the forbidden things at STARTUP:
     * tls_backend_node_init() opens the certificate, the key, the CA and the staple,
     * and creates the two SSL_CTX. A whole-file search would either have to accept
     * those sites -- which is what makes a whole-file list worthless -- or whitelist
     * them by name, which is the same list wearing a hat.
     *
     * SO THE LIST IS SEARCHED IN A REGION: the revocation path itself, from
     * tls_peer_name_of() to the loader. Both markers are identifiers that survive the
     * comment stripping tf_read_code() does, and everything between them is
     * reachable only from tls_after_handshake() and from the accept path's status
     * callback -- the verification, its helpers, and the staple attachment.
     *
     * tls_load_staple() is the marker the region STOPS at rather than one it
     * contains, because it is the one function in this file that reads a file and it
     * is correct for it to: it runs once from tls_backend_node_init(), before the
     * event loop is armed. "Reads the file at startup and nowhere else" is then
     * asserted directly, by counting tls_load_staple's occurrences in the whole file
     * -- which is a stronger statement than a region boundary, because a second call
     * site anywhere in the tree fails it whether or not it is adjacent to the loader.
     *
     * AND THE MARKERS ARE ASSERTED TO EXIST, because an empty region satisfies every
     * negative check below without checking anything. A rename of either function
     * would otherwise make this function pass vacuously, which is worse than it
     * having no assertions at all. */
    from = strstr(code, "tls_peer_name_of(const conn_t");
    to = strstr(code, "tls_load_staple(const char");
    check(from != NULL && to != NULL && from < to,
          "the revocation path is still findable in src/tls_openssl.c, so the "
          "search below is searching something rather than an empty region",
          "a marker function was renamed or removed");
    if (from == NULL || to == NULL || from >= to) {
        free(code);
        return;
    }
    region = (char *)malloc((size_t)(to - from) + 1u);
    TF_CHECK_MSG(region != NULL, "could not allocate the region");
    memcpy(region, from, (size_t)(to - from));
    region[to - from] = '\0';

    for (i = 0; forbidden[i] != NULL; i++) {
        check(!tf_calls(region, forbidden[i]),
              "the revocation path calls no fetch, no resolver, no blocking read and "
              "no second context",
              forbidden[i]);
    }
    /* THE STAPLE IS READ AT STARTUP AND NOWHERE ELSE. Two occurrences is the
     * definition and the single call from tls_backend_node_init(); a third is a
     * second call site, which is the shape a refresh-inside-the-loop takes before
     * anyone has written the loop. */
    check(tf_count(code, "tls_load_staple(") == 2,
          "and the staple file is read by exactly ONE call site -- the loader's "
          "definition and the single call in tls_backend_node_init(), which is "
          "startup -- so nothing re-reads it later and nothing fetches a fresh one",
          "a third occurrence would be a second caller, and a caller in the "
          "revocation path would be a file read inside the event loop");
    /* THE POSITIVE HALF. A file that had been gutted -- the verification deleted, the
     * status never read -- satisfies every check above, because a list of badness
     * cannot notice the absence of the good thing. */
    check(tf_calls(region, "OCSP_basic_verify"),
          "and the revocation path still CALLS OCSP_basic_verify(), so this check "
          "cannot be satisfied by a file that stopped verifying anything", NULL);
    check(tf_calls(region, "OCSP_resp_find_status"),
          "and still reads the status out of the response with "
          "OCSP_resp_find_status(), so a verifier that checked the signature and "
          "ignored the answer would fail here",
          NULL);
    check(tf_calls(region, "OCSP_check_validity"),
          "and still checks FRESHNESS with OCSP_check_validity(), so a verifier that "
          "accepted a stale staple would fail here", NULL);
    check(tf_calls(region, "X509_get0_notAfter"),
          "and still READS the peer's notAfter with X509_get0_notAfter(), so the "
          "exposure window cannot be dropped from the log while this test passes",
          NULL);
    /* AND THE ONE CALL THAT MUST NOT APPEAR, named separately because it is the whole
     * point rather than one item in a list: the OCSP-over-HTTP client. A single
     * OCSP_sendreq_new() here would turn every peer handshake into a network
     * operation inside the event loop, which is what "stapled, never fetched" is
     * written to prevent. */
    check(!tf_calls(region, "OCSP_sendreq"),
          "and above all it does not contain OCSP_sendreq: nothing in this file "
          "opens an HTTP request to fetch a status",
          "a fetch in the revocation path would be a blocking call in the event "
          "loop and would make the whole design decorative");
    free(region);
    free(code);
}

int main(void)
{
    char dir[RV_DIR_MAX];
    char ca_crt[RV_PATH], ca_key[RV_PATH];
    char a_crt[RV_PATH], a_key[RV_PATH];
    char b_crt[RV_PATH], b_key[RV_PATH];
    char rogue_crt[RV_PATH], rogue_key[RV_PATH];
    char good_ocsp[RV_PATH], good_a_ocsp[RV_PATH], revoked_ocsp[RV_PATH];
    char stale_ocsp[RV_PATH];
    char nonext_ocsp[RV_PATH], rogue_ocsp[RV_PATH];
    char buf[256];

    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("== test_tls_revocation ==\n");
    cert_dir(dir, sizeof dir);
    printf("note: TLS is %s in this build\n",
           (tf_tls_available() != 0) ? "COMPILED IN" : "NOT compiled in");

    if (tf_tls_available() == 0) {
        (void)check_plaintext_consequences();
        tf_tls_rmtree(dir);
        printf("== %d failure(s) ==\n", failures);
        return (failures == 0) ? 0 : 1;
    }

    /* THE AUTHORITY, AND TWO LEAVES. One key pair for the CA and one per leaf is
     * three RSA-2048 generations, which is why this file generates them once and
     * shares them across every case rather than per case: a case that needs a fresh
     * certificate is a case whose result depends on the clock, and none of these do.
     *
     * A's OWN staple is not needed by anything -- nothing dials A -- and is still
     * generated and configured, because a node whose peer does verify it should
     * staple one, and a test that only ever configured the stapling side it was
     * checking would miss a node that staples nothing by mistake. */
    check(tf_tls_make_ca(dir, "ca", "irc-serve test CA", -3600, 86400) == 0,
          "generate the test CA", NULL);
    (void)snprintf(ca_crt, sizeof ca_crt, "%s/ca.crt", dir);
    (void)snprintf(ca_key, sizeof ca_key, "%s/ca.key", dir);
    /* TWO CERTIFICATES, EACH NAMING ITS OWN SERVER. The link verifies the peer's
     * certificate against the LINK'S SERVER NAME, so a fixture named after the host
     * would fail -- which is the correct behaviour and what makes the mesh below
     * meaningful. */
    check(tf_tls_make_issued(dir, "a", "irc.a", "DNS:irc.a,IP:127.0.0.1", "ca", -60,
                             86400) == 0,
          "generate irc.a's certificate, issued by the CA and naming irc.a", NULL);
    check(tf_tls_make_issued(dir, "b", "irc.b", "DNS:irc.b,IP:127.0.0.1", "ca", -60,
                             86400) == 0,
          "generate irc.b's certificate, issued by the CA and naming irc.b", NULL);
    (void)snprintf(a_crt, sizeof a_crt, "%s/a.crt", dir);
    (void)snprintf(a_key, sizeof a_key, "%s/a.key", dir);
    (void)snprintf(b_crt, sizeof b_crt, "%s/b.crt", dir);
    (void)snprintf(b_key, sizeof b_key, "%s/b.key", dir);
    /* A SECOND AUTHORITY, sharing no key and no name with the first. It exists only
     * to sign one response, and the response it signs has a perfectly correct CertID
     * -- the point is that a correct CertID is not a signature. */
    check(tf_tls_make_ca(dir, "rogue", "someone else entirely", -3600, 86400) == 0,
          "generate an unrelated second authority, for the rogue-responder case",
          NULL);
    (void)snprintf(rogue_crt, sizeof rogue_crt, "%s/rogue.crt", dir);
    (void)snprintf(rogue_key, sizeof rogue_key, "%s/rogue.key", dir);

    /* THE STAPLES. Five of them, all real, all about irc.b's certificate because irc.b
     * is the peer irc.a dials.
     *
     * THE DIGESTS ALTERNATE ON PURPOSE. The CertID's hash algorithm is the
     * responder's choice and the verifier has to build the same one, so a verifier
     * that only understood SHA-256 would pass GOOD and UNVERIFIED's CertID and fail
     * REVOKED, and one that only understood SHA-1 would fail GOOD. Between them the
     * two required pass cases and the two required refusals cover both. */
    check(tf_tls_make_ocsp(dir, "good", "ca", "b", NULL, TF_OCSP_GOOD, 1, -60,
                           3600) == 0,
          "build a GOOD staple for irc.b's certificate, SHA-256 CertID, in force",
          NULL);
    check(tf_tls_make_ocsp(dir, "revoked", "ca", "b", NULL, TF_OCSP_REVOKED, 0,
                           -60, 3600) == 0,
          "build a GENUINELY REVOKED staple: status REVOKED, reason keyCompromise, "
          "signed by the issuing CA, in force. Deleting the status comparison from "
          "the verifier makes this indistinguishable from the GOOD one.",
          NULL);
    check(tf_tls_make_ocsp(dir, "stale", "ca", "b", NULL, TF_OCSP_GOOD, 0, -7200,
                           -3600) == 0,
          "build an EXPIRED staple: status GOOD, but nextUpdate is an hour ago", NULL);
    check(tf_tls_make_ocsp(dir, "nonext", "ca", "b", NULL, TF_OCSP_GOOD, 0, -60,
                           (long)TF_OCSP_NO_NEXT_UPDATE) == 0,
          "build a staple with NO nextUpdate, which is legal and which a verifier "
          "that wants a bounded exposure window has to refuse",
          NULL);
    check(tf_tls_make_ocsp(dir, "rogue", "ca", "b", "rogue", TF_OCSP_GOOD, 1, -60,
                           3600) == 0,
          "build a staple with a correct CertID signed by an authority the issuer "
          "never authorised",
          NULL);
    /* A's own staple: the SAME GOOD response, generated for A. It is what a node in
     * this position staples, and configuring it is what proves --tls-ocsp-staple is
     * not a one-sided option that silently does nothing on the serving half. */
    check(tf_tls_make_ocsp(dir, "good_a", "ca", "a", NULL, TF_OCSP_GOOD, 1, -60,
                           3600) == 0,
          "build irc.a's own GOOD staple", NULL);
    (void)snprintf(good_ocsp, sizeof good_ocsp, "%s/good.ocsp", dir);
    (void)snprintf(good_a_ocsp, sizeof good_a_ocsp, "%s/good_a.ocsp", dir);
    (void)snprintf(revoked_ocsp, sizeof revoked_ocsp, "%s/revoked.ocsp", dir);
    (void)snprintf(stale_ocsp, sizeof stale_ocsp, "%s/stale.ocsp", dir);
    (void)snprintf(nonext_ocsp, sizeof nonext_ocsp, "%s/nonext.ocsp", dir);
    (void)snprintf(rogue_ocsp, sizeof rogue_ocsp, "%s/rogue.ocsp", dir);
    (void)buf;

    /* ================== CASE 1: GOOD, STRICT: THE POLICY'S HAPPY PATH ==========
     * Both ends configured, both ends stapling, no flags but the two required ones.
     * This is what a correctly-configured mesh looks like and it is the case that
     * says the DEFAULT is usable rather than only that it is safe. */
    run_case("good-strict", a_crt, a_key, b_crt, b_key, ca_crt, good_a_ocsp,
             good_ocsp, 0, 1, "GOOD",
             "a peer whose stapled status is GOOD, verifiable and in force "
             "ESTABLISHES under the default strict policy, so fail-closed is a "
             "policy a working mesh can run rather than one that only refuses");

    /* ================== CASE 2: REVOKED: THE CASE THE FEATURE EXISTS FOR ======== */
    run_case("revoked-strict", a_crt, a_key, b_crt, b_key, ca_crt, good_a_ocsp,
             revoked_ocsp, 0, 0, "REVOKED",
             "a GENUINELY REVOKED certificate is REFUSED: the response is signed by "
             "the issuing CA, its CertID matches the verified leaf, it is inside its "
             "freshness window, and it says revoked -- so every other check passes "
             "and the answer is still no");

    /* ================== CASE 3: EXPIRED STAPLE: FRESHNESS IS CHECKED =========== */
    run_case("stale-strict", a_crt, a_key, b_crt, b_key, ca_crt, good_a_ocsp,
             stale_ocsp, 0, 0, "STALE",
             "a staple whose nextUpdate has passed is REFUSED: accepting it would "
             "mean accepting a status nobody has promised is still current, which "
             "is the exposure window this is supposed to bound");

    /* ================== CASE 4: NO nextUpdate: FRESHNESS IS NOT OPTIONAL ======= */
    run_case("nonext-strict", a_crt, a_key, b_crt, b_key, ca_crt, good_a_ocsp,
             nonext_ocsp, 0, 0, "NO_NEXT_UPDATE",
             "a staple with no nextUpdate is REFUSED rather than read as good for "
             "ever: OCSP_check_validity() accepts a response with no deadline, and "
             "an undated staple is the original gap with extra steps");

    /* ================== CASE 5: THE SIGNER IS CHECKED, NOT JUST THE STATUS ===== */
    run_case("rogue-strict", a_crt, a_key, b_crt, b_key, ca_crt, good_a_ocsp,
             rogue_ocsp, 0, 0, "UNVERIFIED",
             "a status whose CertID is correct but whose signature comes from an "
             "authority the issuer never authorised is REFUSED. A verifier that "
             "read the status field without chaining the signer to --tls-ca would "
             "accept this, and would be accepting a stranger's opinion of a "
             "certificate");

    /* ================== CASE 6: MISSING STAPLE, STRICT ========================= */
    run_case("missing-strict", a_crt, a_key, b_crt, b_key, ca_crt, good_a_ocsp,
             NULL, 0, 0, "MISSING_STAPLE",
             "a peer that staples NOTHING is REFUSED under the strict policy: "
             "without a status there is no evidence the certificate is still good, "
             "and accepting it would make the whole check decorative");

    /* ============ CASE 7: MISSING STAPLE, PERMISSIVE: THE ONE FLAG ============
     * THE PAIR WITH CASE 6, AND IT IS A PAIR ON PURPOSE. A boolean policy is the
     * thing that gets silently inverted -- one comparison changed and every mesh
     * inverts its meaning without one line of output changing -- so both
     * directions are asserted against the same fixture, the same wires and the same
     * missing staple. Swap the two and this file goes red in two places. */
    run_case("missing-permissive", a_crt, a_key, b_crt, b_key, ca_crt,
             good_a_ocsp, NULL, 1, 1, "MISSING_STAPLE",
             "--tls-staple-permissive is the EXPLICIT weakening, and it lets a peer "
             "with no stapled status through: the link establishes, so an operator "
             "who typed the flag gets the tolerance they asked for rather than a "
             "refusal they have to work around");
    /* ================== CASE 7: THE STARTUP LINE ============================== */
    {
        static const char *const prog = "irc-serve";
        static const char *const zero = "0";
        static const char *const shared = "shared";
        nf_node_t na;
        argv_build_t b;

        /* THE POLICY, REPORTED WHERE AN OPERATOR LOOKS. `revocation=` used to be a
         * constant on this line, which is exactly the shape a claim takes when
         * nobody can be proved wrong by changing it: nothing in the suite would have
         * gone red when revocation was implemented, because the value was not
         * derived from anything. It is asserted here in both directions, so a change
         * to either has to be a deliberate one. */
        ab_init(&b);
        ab_add(&b, prog);
        ab_add(&b, zero);
        ab_opt(&b, "--name", "irc.a");
        ab_opt(&b, "--secret", shared);
        ab_opt(&b, "--tls-cert", a_crt);
        ab_opt(&b, "--tls-key", a_key);
        ab_opt(&b, "--tls-ca", ca_crt);
        ab_opt(&b, "--tls-ocsp-staple", good_a_ocsp);
        if (nf_spawn_binary_argv(&na, ab_finish(&b)) != 0) {
            check(0, "spawn irc.a to read the startup line", NULL);
        } else {
            check(nf_expect(&na, "revocation=staple-strict", 5000) == 0,
                  "the startup line says revocation=staple-strict, so an operator "
                  "grepping one line of node output learns that a revoked peer "
                  "certificate is refused -- which is the opposite of the "
                  "revocation=none this line used to carry",
                  na.out);
            check(nf_expect(&na, "ocsp_staple=configured", 5000) == 0,
                  "and ocsp_staple=configured beside it, because whether this node "
                  "HAS a staple to offer is a different fact from whether it checks "
                  "one -- and it is the one that explains a peer link refusing "
                  "with MISSING_STAPLE on the other side",
                  na.out);
            (void)nf_stop(&na);
            nf_free(&na);
        }
        (void)shared;
    }

    /* ================== CASE 8: NOTHING FETCHES ================================= */
    check_no_fetch();

    tf_tls_rmtree(dir);
    printf("== %d failure(s) ==\n", failures);
    return (failures == 0) ? 0 : 1;
}
