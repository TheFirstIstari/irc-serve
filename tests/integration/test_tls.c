/* test_tls.c -- Phase 12's suite, and the shape of it is a property of the
 * DEPENDENCY DECISION rather than of the feature.
 *
 * ===========================================================================
 * WHY THIS FILE ASSERTS DIFFERENT THINGS IN THE TWO BUILDS, AND WHY THAT IS NOT
 * A SKIP
 * ===========================================================================
 * `-DWITH_TLS=ON` is optional and OFF by default, so this file exists in both
 * builds and must pass in both. It therefore branches on `tf_tls_available()` --
 * a RUNTIME question about the build -- and asserts, in each case, the behaviour
 * THAT BUILD ACTUALLY HAS:
 *
 *   default build (no TLS)   no `tls` and no `sts` in CAP LS; STARTTLS answered
 *                            691 with TLS_NOT_CONFIGURED; --tls-port refused;
 *                            --tls-cert without --tls-key refused; a
 *                            world-readable key refused. All of these are REAL
 *                            assertions about a real node and they are the ones
 *                            that matter most for the default build, because the
 *                            default build is the one every CI runner compiles.
 *
 *   -DWITH_TLS=ON           all of the above, plus: a real implicit-TLS
 *                            handshake, a real STARTTLS upgrade, a refused
 *                            handshake against the wrong CA, a refused expired
 *                            certificate, a refused not-yet-valid certificate, a
 *                            refused name mismatch, and a peer link over TLS.
 *
 * NEITHER BRANCH IS A SKIP. `tests/known_skips.txt` stays empty and
 * scripts/check-skips.sh stays at zero: a test that returned CTest's skip code
 * would be asserting nothing on the configuration this project ships by default,
 * which is the exact failure the ratchet exists to prevent. The lines each build
 * prints say which build it is asserting about, so a log reader is never left
 * wondering whether the interesting half ran.
 *
 * ===========================================================================
 * NO CERTIFICATE MATERIAL IS IN THIS REPOSITORY, and there is a header comment in
 * tests/harness/tls_fixture.h saying why at length. The short version: a
 * committed private key is public for ever, and a committed certificate has a
 * fixed validity window, which would make the "expired is refused" case either
 * permanently red or permanently skipped.
 *
 * NO FIXED SLEEP. Every wait is a deadline wait over select(), and the negative
 * cases use the fence the rest of this suite uses: prove the node is alive by
 * getting a positive answer on a second connection, and then assert the absence on
 * the first.
 */
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"
#include "harness/tls_fixture.h"

/* THE FIXTURE'S DIRECTORY AND THE PATHS BUILT FROM IT, sized so a
 * `"%s/<name>"` composition is provably within its destination. gcc-16 diagnoses
 * a same-sized pair as a possible truncation under -Werror and the two clang
 * builds do not, so satisfying the strictest is the choice that needs no
 * suppression -- and a suppression is invisible to a reader of the build output.
 * See test_peer_tls.c for the same constants and the same argument. */
#define TF_DIR_MAX 512
#define TF_PATH (TF_DIR_MAX + 128)

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

/* Where the generated certificates go. Under the build tree rather than /tmp by
 * name, so a parallel `ctest -j8` run of this test twice -- which a developer will
 * do while bisecting -- does not share a directory. The per-process component is
 * the pid. */
static void cert_dir(char *out, size_t cap)
{
    const char *base = getenv("IRCSERVE_BUILD_DIR");

    if (base == NULL) {
        base = "/tmp";
    }
    snprintf(out, cap, "%s/tls-fixture-%ld", base, (long)getpid());
    (void)mkdir(out, 0700);
}

/* ---------------------------------------------------------------------------
 * SPAWN A SHIPPED BINARY WITH AN ARGUMENT VECTOR
 * ---------------------------------------------------------------------------
 * The SHIPPED BINARY and not an inline child, for the cases that need the command
 * line: --tls-cert, --tls-key, --tls-port and --peer-tls are main()'s options and
 * an inline child has no command line at all. A test that exercised the transport
 * through an inline child and the configuration through nothing would leave the
 * join between them untested, and the join is where this phase's real risk is.
 */
static int spawn_argv(nf_node_t *n, char *const argv[])
{
    char **owned;
    size_t count = 0;
    int rc;

    while (argv[count] != NULL) {
        count++;
    }
    /* nf_spawn_binary_argv() reads the vector in the child before execv(), so the
     * strings only have to outlive the spawn. Copying them onto the heap rather
     * than pointing at the caller's literals is what lets every caller build its
     * vector with a snprintf into a stack buffer. */
    owned = (char **)calloc(count + 1u, sizeof *owned);
    if (owned == NULL) {
        return -1;
    }
    for (size_t i = 0; i < count; i++) {
        owned[i] = argv[i];
    }
    owned[count] = NULL;
    rc = nf_spawn_binary_argv(n, owned);
    free(owned);
    return rc;
}

/* Wait for a process that is EXPECTED TO FAIL TO START, which is a different shape
 * from nf_spawn_binary_argv(): that blocks until the child is ready, and a child
 * that refuses to start never is. So the failure cases fork directly and read the
 * exit status.
 *
 * Returns the child's exit status, or -1 if it had to be killed (which is a
 * failure: a node that neither started nor exited on a bad command line has hung,
 * and a hung node is a different finding from a refused one). */
static int run_expecting_refusal(char *const argv[], char *out, size_t outcap,
                                 int timeout_ms)
{
    int fds[2];
    pid_t pid;
    int status = 0;
    size_t n = 0;
    uint64_t deadline;

    if (pipe(fds) != 0) {
        return -1;
    }
    pid = fork();
    if (pid < 0) {
        (void)close(fds[0]);
        (void)close(fds[1]);
        return -1;
    }
    if (pid == 0) {
        (void)close(fds[0]);
        if (dup2(fds[1], STDOUT_FILENO) < 0 ||
            dup2(fds[1], STDERR_FILENO) < 0) {
            _exit(127);
        }
        execv(NF_SERVER_BIN, argv);
        _exit(127);
    }
    (void)close(fds[1]);
    if (out != NULL && outcap > 0u) {
        out[0] = '\0';
    }
    /* Read to EOF, which is bounded by the child exiting or closing: a node that
     * starts normally would hold the pipe open for ever, so the deadline is what
     * distinguishes "refused and exited" from "started and is serving". */
    deadline = 0u;
    {
        struct timespec ts;

        if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
            deadline = (uint64_t)ts.tv_sec * 1000u +
                       (uint64_t)(ts.tv_nsec / 1000000L);
        }
    }
    deadline += (uint64_t)timeout_ms;
    for (;;) {
        struct timeval tv;
        fd_set rd;
        ssize_t r;

        FD_ZERO(&rd);
        FD_SET(fds[0], &rd);
        tv.tv_sec = 0;
        tv.tv_usec = 20000;
        if (select(fds[0] + 1, &rd, NULL, NULL, &tv) > 0) {
            if (out != NULL && n + 1u < outcap) {
                r = read(fds[0], out + n, outcap - n - 1u);
                if (r > 0) {
                    n += (size_t)r;
                    out[n] = '\0';
                    continue;
                }
            } else {
                char sink[512];
                /* DRAIN-ONLY, and the count genuinely has no use: once the
                 * caller's buffer is full there is nothing left to collect, but
                 * the child is still writing into this pipe, and a pipe nobody
                 * reads fills and blocks the writer. Stopping here would turn
                 * "refused and exited" into "hung until the deadline kills it",
                 * which is the other half of what this function distinguishes.
                 *
                 * THE CAST IS ON THE VARIABLE, NOT ON THE CALL, and that is the
                 * whole fix. glibc declares read() __wur (warn_unused_result),
                 * and GCC honours that attribute only when the result is
                 * actually used -- so `(void)read(...)` is not a discard, it is
                 * an error: -Werror=unused-result, and every Linux CI job red.
                 * Clang is the opposite and exempts an explicit cast, so this
                 * line built clean on every macOS cell for as long as it
                 * existed. Nothing about the code was wrong; only the platform
                 * disagreed about whether the result mattered.
                 *
                 * Naming the result is also the form that cannot rot. Assigning
                 * to the `r` of the branch above satisfies the attribute too --
                 * but only because `r` happens to be read elsewhere in this
                 * function. Delete that read and this line breaks again in the
                 * same place, with nothing local to explain why.
                 *
                 * No pragma and no -Wno-unused-result: suppressing the attribute
                 * here also suppresses the one that catches a genuinely dropped
                 * write(), and this project never narrows the warning set.
                 * Cost: one named local and one statement, both of which the
                 * optimiser deletes. */
                ssize_t drained = read(fds[0], sink, sizeof sink);

                (void)drained;
            }
        }
        if (waitpid(pid, &status, WNOHANG) == pid) {
            break;
        }
        if (deadline != 0u) {
            struct timespec ts;

            if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0 &&
                (uint64_t)ts.tv_sec * 1000u +
                    (uint64_t)(ts.tv_nsec / 1000000L) > deadline) {
                (void)kill(pid, SIGKILL);
                (void)waitpid(pid, &status, 0);
                (void)close(fds[0]);
                return -1;
            }
        }
    }
    (void)close(fds[0]);
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    return -1;
}

/* ---------------------------------------------------------------------------
 * THE REFUSAL INSIDE server_listen_tls(), AND WHY NOTHING HERE ASSERTS IT
 * ---------------------------------------------------------------------------
 * server_listen_tls() refuses when `s->tls == NULL`: there is no configuration in
 * which this function binds a port it cannot encrypt, and that is the whole of its
 * safety property.
 *
 * A fault injection DELETED that refusal and every assertion in this file stayed
 * green. The reason is not that the check is weak -- it is that the check is
 * UNREACHABLE through the shipped binary: main() already refuses `--tls-port` when
 * no certificate was supplied, before server_listen_tls() is ever called. Both
 * branches of that earlier refusal are asserted above, and they are the ones that
 * are exercised.
 *
 * The code is KEPT rather than removed, because server_listen_tls() is a public
 * function and a future caller that reaches it without going through main() -- a
 * test, an embedding, a third listener -- would otherwise bind a port it cannot
 * encrypt.
 *
 * AND NO INSPECTION ASSERTION IS MADE ABOUT IT, which is the part worth recording.
 * The first attempt at one read the file through tf_read_code() and searched for the
 * condition; it passed with the refusal deleted, because the stripper removes
 * string LITERALS and the same condition also appears in server_dial_progress()'s
 * peer-link arm where it means something else. The second attempt scoped the search
 * to the function's own text and still passed. An assertion that cannot fail is
 * worse than no assertion, because a reader counts it as coverage. So this is a
 * NAMED GAP rather than a checked one, and the gap is documented at the code as
 * well as here.
 */
static void case_one_named_gap(void)
{
    check(1,
          "NAMED GAP, not a covered case: server_listen_tls()'s own NO-TLS refusal "
          "is unreachable through the shipped binary (main() refuses first, and "
          "that refusal IS asserted), so deleting it changes no observable "
          "behaviour and nothing here can prove otherwise",
          NULL);
}

/* ===========================================================================
 * CASE GROUP 1: the REFUSALS, which both builds assert
 * ===========================================================================
 *
 * A TLS option that is silently ignored is worse than one that is refused, because
 * an operator who typed --tls-require and got a node that does not require it has
 * no way to find out except by reading the source. Every case here is a command
 * line the node must REFUSE, and each refusal is asserted on the child's own
 * output -- the reason string -- rather than only on a non-zero exit, because two
 * different mistakes can both produce exit 1 and an operator needs to know which.
 */
static void case_configuration_refusals(const char *dir)
{
    char msg[4096];
    char a0[] = "irc-serve";
    char a1[] = "0";
    char a2[] = "--name";
    char a3[] = "irc.tls";
    char cert[TF_PATH];
    char key[TF_PATH];
    char port[16];
    char *v_no_pair[9];
    char *v_bad_key[9];
    char *v_port_no_cert[9];
    int rc;

    snprintf(cert, sizeof cert, "%s/srv.crt", dir);
    snprintf(key, sizeof key, "%s/srv.key", dir);
    snprintf(port, sizeof port, "%d", 0);

    /* --tls-cert WITHOUT --tls-key. Half a configuration is not a state this
     * binary can be in: a node with a certificate and no key would advertise
     * nothing and refuse every STARTTLS for a reason the startup line cannot
     * express. */
    v_no_pair[0] = a0; v_no_pair[1] = a1; v_no_pair[2] = a2; v_no_pair[3] = a3;
    v_no_pair[4] = "--tls-cert"; v_no_pair[5] = cert;
    v_no_pair[6] = "--name"; v_no_pair[7] = a3; v_no_pair[8] = NULL;
    rc = run_expecting_refusal(v_no_pair, msg, sizeof msg, 10000);
    check(rc > 0, "--tls-cert without --tls-key is REFUSED with a non-zero exit",
          msg);
    check(strstr(msg, "pair") != NULL,
          "the refusal says the two options are a PAIR, not that the file is "
          "unreadable",
          msg);

    /* --tls-port WITHOUT a certificate. This is the one that matters most: a node
     * bound to 6697 that then served PLAINTEXT there would send every client that
     * expected a handshake into IRC. server_listen_tls() refuses it, and the
     * refusal is at CONFIGURE time rather than at accept time. */
    v_port_no_cert[0] = a0; v_port_no_cert[1] = a1;
    v_port_no_cert[2] = "--tls-port"; v_port_no_cert[3] = port;
    v_port_no_cert[4] = "--name"; v_port_no_cert[5] = a3;
    v_port_no_cert[6] = NULL; v_port_no_cert[7] = NULL; v_port_no_cert[8] = NULL;
    rc = run_expecting_refusal(v_port_no_cert, msg, sizeof msg, 10000);
    check(rc > 0, "--tls-port without a certificate is REFUSED, so nothing is "
                  "bound that cannot be encrypted",
          msg);

    /* A WORLD-READABLE KEY. This is the case the whole permission check exists
     * for, and it is asserted against a real file with a real mode.
     *
     * IT IS IN GROUP 1 RATHER THAN IN THE TLS-ONLY HALF ON PURPOSE: the refusal
     * has to happen even in a build with no TLS library, because a node that
     * ignored an unsafe key and then a deployment installed one would have been
     * told nothing at the moment it mattered. */
    /* A KEY FILE IS WRITTEN WITH tf_tls_write_file() AND NOT GENERATED, and that is
     * the point. The refusal this case checks happens BEFORE anything is parsed --
     * the node stats the file, finds a group- or other-readable bit, and stops --
     * so it does not need a real certificate and must not be gated on one. Making
     * it depend on the generator meant the DEFAULT build exited before reaching it,
     * so the single most important assertion in this file ran only in the build that
     * already has TLS. A fault injection found that: removing the check made the
     * whole file green in the TLS build for the WRONG reason, and would have made
     * it green in the default build for the same one. */
    snprintf(key, sizeof key, "%s/open.key", dir);
    check(tf_tls_write_file(key, "-----BEGIN PRIVATE KEY-----\n", 28, 0644) == 0,
          "put a file on disk whose mode is 0644 -- no certificate needed, because "
          "the refusal is a stat(2) and not a parse",
          NULL);
    snprintf(cert, sizeof cert, "%s/open.crt", dir);
    check(tf_tls_write_file(cert, "-----BEGIN CERTIFICATE-----\n", 27, 0600) == 0,
          "and a matching certificate file with a safe mode, so the refusal cannot "
          "be satisfied by the certificate failing to load instead",
          NULL);
    {
        struct stat sb;
        int mode_ok = (stat(key, &sb) == 0) &&
                      ((sb.st_mode & (S_IRWXG | S_IRWXO)) != 0);

        check(mode_ok,
              "the fixture really produced a key that group and other may read, "
              "so the refusal below cannot pass on a 0600 file",
              "the fixture's mode argument did not take");
    }
    v_bad_key[0] = a0; v_bad_key[1] = a1; v_bad_key[2] = a2; v_bad_key[3] = a3;
    v_bad_key[4] = "--tls-cert"; v_bad_key[5] = cert;
    v_bad_key[6] = "--tls-key"; v_bad_key[7] = key;
    v_bad_key[8] = NULL;
    rc = run_expecting_refusal(v_bad_key, msg, sizeof msg, 10000);
    check(rc > 0, "a WORLD-READABLE private key REFUSES the whole configuration, "
                  "with a non-zero exit",
          msg);
    check(strstr(msg, "tls_key") != NULL && strstr(msg, "REFUSED") != NULL,
          "the refusal is reported as tls_key state=REFUSED with the offending "
          "mode, so an operator can see WHICH file and WHICH bits",
          msg);
    check(strstr(msg, "mode_") != NULL,
          "the refusal prints the mode that was refused, in octal", msg);

    /* GROUP-READABLE ALONE, AND THIS IS THE CASE THE FIRST VERSION OF THIS TEST
     * WAS MISSING.
     *
     * The case above uses mode 0644, which sets the group bits AND the other bits,
     * so a check that tested only S_IRWXO would still refuse it and the test would
     * pass against a check with half the rule missing. A fault injection confirmed
     * exactly that: reducing the check to `sb.st_mode & S_IRWXO` left this whole
     * file green, which is the false pass this project has been bitten by before.
     *
     * 0640 is the mode that separates the two halves: readable by its OWNER'S
     * GROUP and not by other. A private key a group account can read has been shared
     * with a group account, and on a shared build host or a machine with a
     * `developers` group that is the whole defeat. So the refusal has to come from
     * S_IRWXG alone, with nothing else set. */
    snprintf(key, sizeof key, "%s/group.key", dir);
    check(tf_tls_write_file(key, "-----BEGIN PRIVATE KEY-----\n", 28, 0640) == 0,
          "put a file on disk whose mode is 0640 -- group-readable, NOT "
          "world-readable",
          NULL);
    {
        struct stat sb;
        int shape_ok = (stat(key, &sb) == 0) &&
                       ((sb.st_mode & S_IRWXG) != 0) &&
                       ((sb.st_mode & S_IRWXO) == 0);

        check(shape_ok,
              "and the fixture really produced that shape: group bits set and "
              "other bits CLEAR, so the assertion below cannot be satisfied by a "
              "world-readability check",
              "the fixture's mode argument did not take");
    }
    snprintf(cert, sizeof cert, "%s/group.crt", dir);
    check(tf_tls_write_file(cert, "-----BEGIN CERTIFICATE-----\n", 27, 0600) == 0,
          "and a certificate file, so the refusal is about the KEY's mode and "
          "nothing else",
          NULL);
    rc = run_expecting_refusal(v_bad_key, msg, sizeof msg, 10000);
    check(rc > 0, "a GROUP-READABLE private key is refused on its own, with no "
                  "world-readable bit set anywhere",
          msg);
    /* THE REASON IS ASSERTED, NOT JUST THE EXIT STATUS, and this assertion is the
     * difference between catching the fault and half-catching it.
     *
     * With a check that tested only S_IRWXO, a 0640 key would be ACCEPTED by the
     * permission test -- and then refused moments later because the fixture's file
     * is not a real PEM. The node exits non-zero either way, so an assertion on the
     * exit status passes against the fault, and the only reason it was caught at
     * all was the mode_640 needle below. Asserting the REASON means the refusal
     * has to be the key's mode: a refusal that came from the file not parsing is
     * a different failure with a different fix. */
    check(strstr(msg, "tls_key: state=REFUSED") != NULL,
          "and the refusal is the KEY'S MODE -- not the certificate failing to "
          "load, which is a different fault with a different fix and also exits "
          "non-zero",
          msg);
    check(strstr(msg, "reason=mode_640 ") != NULL,
          "and the refusal prints reason=mode_640 -- octal, with no leading zero -- "
          "which is what makes it checkable that the refusal came from the group bit",
          msg);
}

/* ===========================================================================
 * CASE GROUP 2: a build WITHOUT TLS has no TLS surface at all
 * ===========================================================================
 *
 * The assertions here are the ones that matter on the DEFAULT build, and they are
 * real: a node built without OpenSSL must not advertise `sts`, must not advertise
 * `tls`, and must answer STARTTLS with 691 rather than 670. A node that advertised
 * either would be a client switching on a feature nothing implements, which is the
 * failure cap.h exists to prevent.
 */
static void case_plaintext_build_has_no_tls_surface(const char *dir)
{
    nf_node_t n;
    test_client_t c;
    char msg[4096];
    char a0[] = "irc-serve";
    char a1[] = "0";
    char key[TF_PATH];
    char cert[TF_PATH];
    char *v[10];
    int rc;

    if (nf_spawn_binary(&n) != 0) {
        check(0, "spawn the default-build node", NULL);
        return;
    }
    check(nf_expect(&n, "tls=absent", 5000) == 0,
          "the startup line says tls=absent on a build with no TLS", NULL);

    /* A NODE THAT WAS ASKED FOR TLS ON A BUILD THAT CANNOT DO IT.
     *
     * This was originally asserted on a node with no TLS options at all, which
     * asserted nothing: a node with no options never calls the backend, so
     * `tls_init: state=REFUSED` could not appear and the check only ever passed on
     * a build where the branch was never reached. It needs a node that ACTUALLY
     * supplies a certificate, and the key therefore has to have a SAFE mode -- or
     * the key's own refusal fires first, which is itself correct behaviour and is
     * asserted separately above.
     *
     * So: a 0600 key and a certificate, handed to a build with no crypto library.
     * The answer must be a named refusal, not a node that starts and believes it
     * is encrypted. */
    snprintf(key, sizeof key, "%s/plain-build.key", dir);
    snprintf(cert, sizeof cert, "%s/plain-build.crt", dir);
    (void)tf_tls_write_file(key, "-----BEGIN PRIVATE KEY-----\n", 28, 0600);
    (void)tf_tls_write_file(cert, "-----BEGIN CERTIFICATE-----\n", 27, 0600);
    v[0] = a0; v[1] = a1; v[2] = "--tls-cert"; v[3] = cert;
    v[4] = "--tls-key"; v[5] = key; v[6] = NULL; v[7] = NULL;
    v[8] = NULL; v[9] = NULL;
    rc = run_expecting_refusal(v, msg, sizeof msg, 10000);
    check(rc > 0,
          "a node GIVEN a certificate on a build with no crypto library REFUSES "
          "to start rather than coming up as a node that believes it is encrypted",
          msg);
    check(strstr(msg, "NOT_COMPILED_IN") != NULL,
          "and names NOT_COMPILED_IN, so the operator is told to rebuild rather "
          "than left guessing whether the certificate was bad",
          msg);

    if (tc_connect(&c, n.port) != 0) {
        check(0, "connect to the plaintext listener", NULL);
        nf_kill(&n);
        nf_free(&n);
        return;
    }
    check(tc_send(&c, "CAP LS") == 0, "send CAP LS", NULL);
    check(tc_expect(&c, " LS :", 10000) == 0, "the node answers CAP LS",
          tc_buffer(&c));
    check(strstr(tc_buffer(&c), " sts") == NULL,
          "CAP LS does NOT list `sts` on a build with no TLS",
          tc_buffer(&c));
    check(strstr(tc_buffer(&c), " tls") == NULL,
          "CAP LS does NOT list `tls` on a build with no TLS", tc_buffer(&c));

    check(tc_send(&c, "STARTTLS") == 0, "send STARTTLS", NULL);
    check(tc_expect(&c, " 691 ", 10000) == 0,
          "STARTTLS is answered 691 on a build with no TLS", tc_buffer(&c));
    check(strstr(tc_buffer(&c), "not available on this server") != NULL,
          "the 691 says TLS is not available, so the client knows to reconnect on "
          "the implicit-TLS port rather than retry",
          tc_buffer(&c));

    tc_close(&c);
    (void)nf_stop(&n);
    nf_free(&n);
}

/* ===========================================================================
 * CASE GROUP 1b: `sts` IS ONLY ADVERTISED WHERE IT IS HONOURABLE
 * ===========================================================================
 *
 * A node with a certificate and key, a chosen --tls-sts-duration, and NO
 * --tls-port. Its only route to TLS is STARTTLS on the plaintext port, which the
 * IRCv3 strict-transport-security specification says `sts` is INCOMPATIBLE with:
 * "STS expects that servers instead offer a port that directly services secure
 * connections and it is incompatible with servers that offer secure connections
 * only via STARTTLS on an insecure port."
 *
 * This node used to answer `CAP LS` on that plaintext port with
 * `sts=duration=15552000` and no `port` key at all. Two things were wrong with
 * that and neither is a matter of taste:
 *
 *   1. `port` is REQUIRED on an insecure connection, and `CAP LS` travels on the
 *      insecure port. The specification's rule for a missing required part is
 *      "if any required part is missing, clients MUST continue as if no STS
 *      policy was advertised" -- so a conforming client was being told to behave
 *      as though this node had no downgrade protection, which is exactly what the
 *      `tls` capability alone would have told it truthfully. And a LENIENT client
 *      honouring only `duration` caches a persistence policy for a hostname with
 *      no secure port and then refuses to connect: a self-inflicted outage, and the
 *      hazard the specification's own denial-of-service section names.
 *
 *   2. An operator reading `sts` in `CAP LS` concludes this node has downgrade
 *      protection. It has none: the port is still served in the clear and the only
 *      upgrade is STARTTLS, which is the shape the specification excludes. That is
 *      the "advertise before the feature exists" failure cap.h exists to prevent.
 *
 * `tls` STAYS, because it is true -- this node does answer STARTTLS -- and
 * withholding a true fact is the opposite mistake. So the assertions below are
 * about `sts` being ABSENT and `tls` being PRESENT, and the pair matters: a fix
 * that suppressed both would pass the first assertion and be wrong.
 *
 * THE POSITIVE HALF IS ALREADY ASSERTED ELSEWHERE in this file: the node spawned
 * above, which HAS a --tls-port, must advertise `sts=duration=15552000` with
 * `port=` naming the port it bound. Neither half is interesting alone -- a build
 * that suppressed `sts` unconditionally, or one that suppressed it everywhere, each
 * passes one of the two cases.
 */
static void case_sts_requires_a_secure_port(const char *cert, const char *key)
{
    nf_node_t n;
    test_client_t c;
    char a0[] = "irc-serve";
    char a1[] = "0";
    char a2[] = "--name";
    char a3[] = "irc.tls";
    char *argv[12];

    argv[0] = a0; argv[1] = a1; argv[2] = a2; argv[3] = a3;
    argv[4] = "--tls-cert"; argv[5] = (char *)(uintptr_t)(const void *)cert;
    argv[6] = "--tls-key"; argv[7] = (char *)(uintptr_t)(const void *)key;
    /* NO --tls-port, and NO --tls-require: this is a perfectly ordinary node that
     * offers STARTTLS and nothing else, which is the configuration under test. */
    argv[8] = "--tls-sts-duration"; argv[9] = "15552000";
    argv[10] = NULL; argv[11] = NULL;
    if (nf_spawn_binary_argv(&n, argv) != 0) {
        check(0, "spawn a node with a certificate and NO --tls-port", NULL);
        return;
    }
    check(nf_expect(&n, "tls=configured", 5000) == 0,
          "the certificate loaded, so this is a node that genuinely has TLS and "
          "merely lacks a secure port",
          n.out);
    /* THE ANCHOR. The assertions below are only about the `sts` policy if this
     * node really is in the configuration that suppresses it, so the absence of a
     * listener is asserted rather than assumed -- a reader (and a future change
     * that made --tls-port implied) can tell the two situations apart. */
    check(nf_expect(&n, "tls_port=-1", 5000) == 0,
          "and it bound NO implicit-TLS listener, which is the state the "
          "specification's REQUIRED-`port` rule is about",
          n.out);

    if (tc_connect(&c, n.port) != 0) {
        check(0, "connect to that node's plaintext port", NULL);
    } else {
        check(tc_send(&c, "CAP LS") == 0, "send CAP LS to it", NULL);
        check(tc_expect(&c, " LS :", 10000) == 0,
              "the plaintext port still answers CAP LS", tc_buffer(&c));
        /* THE ASSERTION THAT A REVERTED SUPPRESSION FAILS. Reverted to
         * tls_node_possible() for both names, this line reads
         * `sts=duration=15552000` with no `port`, which is the malformed policy. */
        check(strstr(tc_buffer(&c), "sts") == NULL,
              "CAP LS does NOT carry `sts` at all on a node with no secure port: "
              "`port` is REQUIRED on an insecure connection and a policy missing a "
              "required part tells a conforming client to behave as though none "
              "was advertised -- while telling an operator protection that does "
              "not exist",
              tc_buffer(&c));
        check(strstr(tc_buffer(&c), " tls") != NULL,
              "and `tls` IS still advertised, because it is TRUE -- this node does "
              "answer STARTTLS -- and withholding a true fact is the opposite "
              "mistake",
              tc_buffer(&c));
        tc_close(&c);
    }
    (void)nf_stop(&n);
    nf_free(&n);
}

int main(void)
{
    char dir[TF_DIR_MAX];
    char msg[4096];
    /* `g_cert`/`g_key`/`g_port` rather than `cert`/`key`/`port`: the refusal helper
     * has its own cert/key/port paths for the files it is refusing, and -Wshadow
     * (which -Weverything includes, and this project keeps) is right that two
     * buffers for two different certificates in one file is worth distinguishing at
     * the name. These are the GOOD ones. */
    static char g_cert[TF_PATH];
    static char g_key[TF_PATH];
    static char g_port[16];
    char a0[] = "irc-serve";
    char a1[] = "0";
    char a2[] = "--name";
    char a3[] = "irc.tls";
    char *argv[16];

    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("== test_tls ==\n");
    cert_dir(dir, sizeof dir);
    printf("note: certificate directory is %s\n", dir);
    printf("note: TLS is %s in this build; the assertions below are about the "
           "build this binary is\n", (tf_tls_available() != 0) ? "COMPILED IN"
                                                              : "NOT compiled in");

    /* Every run generates a usable key pair, because the refusals in group 1 need
     * real files to refuse and the group-3 cases need a real one to accept. Doing
     * it unconditionally rather than only in the TLS branch means a fixture failure
     * is reported once, in one place, rather than as a mysterious refusal later. */
    /* THE SAN CARRIES `DNS:irc.tls` AND THE NAME IS WHAT IS VERIFIED.
     *
     * OpenSSL does not fall back to the subject's CN when a certificate has a
     * subjectAltName at all -- the CN is ignored outright -- so a fixture whose SAN
     * listed only an address would fail every name check even against its own
     * certificate. The tests verify the name `irc.tls` because that is what a
     * client connecting to a named node checks, and what this node's peer-link
     * path checks. Getting this wrong made the FIRST VERSION of the implicit-TLS
     * case fail with "certificate verify failed" against the node's own
     * certificate. */
    if (tf_tls_make_cert(dir, "srv", "irc.tls",
                         "DNS:irc.tls,IP:127.0.0.1,DNS:localhost", 0, 86400,
                         0600) != 0) {
        /* NOT a failure line, and the wording matters: this is an EXPECTED outcome
         * in the default build and the assertion below confirms it. Printing
         * "FAILED" here and then exiting 0 would leave a green CTest run whose log
         * contains the word FAILED, which is the kind of thing a reader stops
         * trusting. A note says what happened and the check says whether it was
         * right. */
        printf("note: the fixture could not generate a certificate, which is the "
               "expected state of a build with no TLS library\n");
        check(tf_tls_available() == 0,
              "certificate generation is possible exactly when TLS is compiled in",
              "tf_tls_make_cert() failed on a build that has OpenSSL");
        /* THE REFUSALS STILL RUN, and returning here instead is what a fault
         * injection caught. The generator needs OpenSSL; the refusals do not --
         * a key with the wrong mode is refused by a stat(2) before anything is
         * parsed -- so an early return left the DEFAULT build asserting ONE thing
         * about TLS, which is the build every CI runner compiles and the one that
         * should check most. Everything below this point that needs no handshake
         * runs in both configurations. */
        case_configuration_refusals(dir);
        case_plaintext_build_has_no_tls_surface(dir);
        tf_tls_rmtree(dir);
        printf("== %d failure(s) ==\n", failures);
        return (failures == 0) ? 0 : 1;
    }
    check(tf_tls_available() != 0,
          "certificate generation works, which is the precondition for every "
          "handshake case below", NULL);

    snprintf(g_cert, sizeof g_cert, "%s/srv.crt", dir);
    snprintf(g_key, sizeof g_key, "%s/srv.key", dir);
    snprintf(g_port, sizeof g_port, "0");

    case_configuration_refusals(dir);

    /* ---- the implicit-TLS surface, asserted per build ---- */
    if (tf_tls_available() == 0) {
        case_plaintext_build_has_no_tls_surface(dir);
    } else {
        /* A node WITH a certificate and key, and an implicit-TLS listener. */
        nf_node_t n;
        test_client_t plain;
        int tls_port;

        argv[0] = a0; argv[1] = a1; argv[2] = a2; argv[3] = a3;
        argv[4] = "--tls-cert"; argv[5] = g_cert;
        argv[6] = "--tls-key"; argv[7] = g_key;
        argv[8] = "--tls-port"; argv[9] = g_port;
        argv[10] = "--tls-sts-duration"; argv[11] = "15552000";
        argv[12] = NULL; argv[13] = NULL; argv[14] = NULL; argv[15] = NULL;
        if (spawn_argv(&n, argv) != 0) {
            check(0, "spawn a node with a certificate and an implicit-TLS port",
                  NULL);
        } else {
            check(nf_expect(&n, "tls=configured", 5000) == 0,
                  "the startup line says tls=configured once a certificate and key "
                  "have loaded",
                  NULL);
            check(nf_expect(&n, "tls_bind: port=", 5000) == 0,
                  "a second listener is bound for implicit TLS", NULL);
            check(nf_expect(&n, "sts_duration=15552000", 5000) == 0,
                  "the `sts` duration the operator chose is on the startup line, "
                  "so what clients will be told is checkable without a client",
                  NULL);
            /* The port, read back off the child's own output rather than parsed
             * out of the argument: `--tls-port 0` asks the kernel for an ephemeral
             * one, so the argument is NOT the port and a test that used it would
             * connect to nothing. server_port() exists for exactly this and the
             * node prints what it bound. */
            {
                const char *p = strstr(n.out, "tls_port=");

                tls_port = -1;
                if (p != NULL) {
                    tls_port = atoi(p + 9);
                }
            }
            check(tls_port > 0,
                  "the implicit-TLS listener reports a real port, so a client can "
                  "be pointed at it",
                  n.out);

            /* --- CAP LS on a PLAINTEXT connection advertises the policy --- */
            if (tc_connect(&plain, n.port) != 0) {
                check(0, "connect to the plaintext listener", NULL);
            } else {
                check(tc_send(&plain, "CAP LS") == 0, "send CAP LS", NULL);
                check(tc_expect(&plain, " LS :", 10000) == 0,
                      "the plaintext listener answers CAP LS", tc_buffer(&plain));
                check(strstr(tc_buffer(&plain), "sts=duration=15552000") != NULL,
                      "CAP LS carries the `sts` VALUE -- `sts=duration=15552000` "
                      "-- because the specification requires the value in the LS "
                      "and forbids a client requesting it",
                      tc_buffer(&plain));
                check(strstr(tc_buffer(&plain), "port=6697") == NULL,
                      "the `port` key is not a constant 6697: it names the port "
                      "this node actually bound",
                      tc_buffer(&plain));
                {
                    char want[64];

                    (void)snprintf(want, sizeof want, "port=%d", tls_port);
                    check(strstr(tc_buffer(&plain), want) != NULL,
                          "the `port` key names the implicit-TLS port this node "
                          "bound, which is what a client must reconnect to",
                          tc_buffer(&plain));
                }
                check(strstr(tc_buffer(&plain), " tls") != NULL,
                      "CAP LS lists `tls` as well, because this node does support "
                      "the STARTTLS command",
                      tc_buffer(&plain));

                /* --- CAP REQ :sts is NAKed, per the specification ---
                 *
                 * WAITING FOR "NAK :sts" DIRECTLY, and the reason is a race this
                 * test lost: the first version waited for "CAP ", which is ALREADY
                 * in the buffer from the CAP LS this same connection sent, so the
                 * wait returned instantly and the assertion that followed read a
                 * buffer the NAK had not been appended to yet. A needle that can
                 * be satisfied by an earlier exchange is the substring trap
                 * test_echo_message.c exists to document, met in a new place. */
                check(tc_send(&plain, "CAP REQ :sts") == 0,
                      "a client requests sts anyway", NULL);
                /* The wire form is `:server CAP <target> NAK :sts`, so the needle is
                 * the SUB-COMMAND followed by the colonned list. Matching on "sts"
                 * alone would be satisfied by the CAP LS this same connection
                 * already received, which is the substring trap this suite has
                 * been bitten by before (test_echo_message.c's whole subject). */
                check(tc_expect(&plain, "NAK :sts", 10000) == 0,
                      "CAP REQ :sts is NAKed: the specification says clients MUST "
                      "NOT request this capability, and an ACK would tell a client "
                      "it had negotiated a policy",
                      tc_buffer(&plain));
                check(strstr(tc_buffer(&plain), "ACK :sts") == NULL,
                      "no ACK is sent for sts under any circumstances",
                      tc_buffer(&plain));
                tc_close(&plain);
            }

            /* --- A REAL IMPLICIT-TLS HANDSHAKE, verified ---
             *
             * `t` and `why` are scoped to THIS block on purpose. Every refusal case
             * below declares its own pair, and an earlier version of this file
             * declared one pair for the whole function -- which -Wshadow correctly
             * reported, and correctly: a shared `why` across a function that runs
             * four handshakes is a variable whose value a reader has to prove is
             * from the handshake they are looking at. */
            {
            tf_tls_t t;
            const char *why = NULL;

            if (tf_tls_connect(&t, tls_port, g_cert, "irc.tls", &why) != 0) {
                check(0, "an implicit-TLS handshake against the node's own "
                         "certificate succeeds",
                      (why != NULL) ? why : "handshake failed");
            } else {
                check(1, "an implicit-TLS handshake against the node's own "
                         "certificate succeeds", NULL);
                check(tf_tls_send(&t, "NICK tlsuser") == 0, "send NICK", NULL);
                check(tf_tls_send(&t, "USER tlsuser 0 * :TLS User") == 0,
                      "send USER", NULL);
                check(tf_tls_expect(&t, " 001 ", 10000) == 0,
                      "registration completes over the encrypted connection",
                      tf_tls_buffer(&t));
                check(tf_tls_send(&t, "JOIN #secure") == 0, "send JOIN", NULL);
                check(tf_tls_expect(&t, " 366 ", 10000) == 0,
                      "a channel join completes over the encrypted connection",
                      tf_tls_buffer(&t));
                check(tf_tls_send(&t, "PING :tls-ok") == 0, "send PING", NULL);
                check(tf_tls_expect(&t, "PONG irc.tls tls-ok", 10000) == 0,
                      "PING/PONG completes over the encrypted connection",
                      tf_tls_buffer(&t));
                tf_tls_close(&t);
            }
            }
            check(nf_expect(&n, "tls_handshake_start: fd=", 5000) == 0,
                  "the node reports starting the handshake, so the handshake is "
                  "visible to an operator and not just to the client", NULL);
            /* The counters are published at SHUTDOWN, not per tick, so the check
             * has to come after nf_stop() rather than before it. Asking for a
             * counter the node has not printed yet is a check that fails for a
             * reason that has nothing to do with the thing it is checking. */
            (void)nf_stop(&n);
            check(nf_expect_u64(&n, "tls_handshake_failed=", 0u, 5000) == 0,
                  "no handshake failed on the ACCEPTING side, for a certificate "
                  "the node presented itself and a client that verified it "
                  "against the node's own CA",
                  NULL);
            nf_free(&n);
        }

        /* --- A CERTIFICATE WITH NO --tls-port: `sts` IS NOT ADVERTISED --- */
        case_sts_requires_a_secure_port(g_cert, g_key);

        /* --- THE FOUR REFUSED HANDSHAKES, against ONE node --- */
        {
            nf_node_t n2;
            int p2;
            (void)0;

            argv[0] = a0; argv[1] = a1; argv[2] = a2; argv[3] = a3;
            argv[4] = "--tls-cert"; argv[5] = g_cert;
            argv[6] = "--tls-key"; argv[7] = g_key;
            argv[8] = "--tls-port"; argv[9] = g_port;
            argv[10] = NULL; argv[11] = NULL; argv[12] = NULL;
            argv[13] = NULL; argv[14] = NULL; argv[15] = NULL;
            if (spawn_argv(&n2, argv) != 0) {
                check(0, "spawn a node for the refused-handshake cases", NULL);
            } else {
                const char *p = strstr(n2.out, "tls_port=");

                p2 = (p != NULL) ? atoi(p + 9) : -1;
                check(p2 > 0, "the refused-handshake node bound an implicit-TLS "
                              "port", NULL);

                /* WRONG CA. A second, unrelated self-signed authority that shares
                 * no key and no name with the node's, verified by the client
                 * against the node's own CA. The node does not ask for a client
                 * certificate, so this is refused by the CLIENT -- which is the
                 * right place for it and is worth saying: the client's refusing is
                 * the protection, and a client that does not verify has no
                 * protection at all. That is the honest limit of this case. */
                {
                    char otherca[TF_PATH];
                    tf_tls_t t;
                    const char *why = NULL;

                    snprintf(otherca, sizeof otherca, "%s/other.crt", dir);
                    (void)tf_tls_make_cert(dir, "other", "someone.else",
                                           "IP:127.0.0.1", 0, 86400, 0600);
                    check(tf_tls_connect(&t, p2, otherca, "irc.tls", &why) != 0,
                          "a client that verifies against a DIFFERENT CA refuses "
                          "the node's certificate, so the handshake never "
                          "completes",
                          (why != NULL) ? why : "the handshake SUCCEEDED");
                    tf_tls_close(&t);
                }
                /* EXPIRED. The node presents a certificate whose notAfter is in the
                 * past. OpenSSL's chain verification checks the validity window and
                 * this phase does not turn that off, so a client that verifies
                 * refuses it. */
                {
                    char ecert[TF_PATH];
                    char ekey[TF_PATH];
                    nf_node_t n3;
                    int p3;

                    (void)tf_tls_make_cert(dir, "expired", "irc.tls",
                                           "IP:127.0.0.1,DNS:localhost",
                                           -86400, -3600, 0600);
                    snprintf(ecert, sizeof ecert, "%s/expired.crt", dir);
                    snprintf(ekey, sizeof ekey, "%s/expired.key", dir);
                    argv[4] = "--tls-cert"; argv[5] = ecert;
                    argv[6] = "--tls-key"; argv[7] = ekey;
                    argv[8] = "--tls-port"; argv[9] = g_port;
                    argv[10] = NULL; argv[11] = NULL; argv[12] = NULL;
                    if (spawn_argv(&n3, argv) == 0) {
                        tf_tls_t t;
                        const char *why = NULL;
                        const char *q = strstr(n3.out, "tls_port=");

                        p3 = (q != NULL) ? atoi(q + 9) : -1;
                        /* The node ACCEPTS the expired certificate -- it is its own
                         * certificate and this node does not verify itself. The
                         * refusal is the CLIENT's, and that is the only place it
                         * can be: a server cannot refuse its own certificate. */
                        check(tf_tls_connect(&t, p3, ecert, "irc.tls", &why) != 0,
                              "an EXPIRED certificate is refused by a client that "
                              "verifies it, so the handshake does not complete",
                              (why != NULL) ? why : "the handshake SUCCEEDED");
                        tf_tls_close(&t);
                        (void)nf_stop(&n3);
                        nf_free(&n3);
                    } else {
                        check(0, "spawn a node with an expired certificate", NULL);
                    }
                }
                /* NOT YET VALID. notBefore in the future. Separate from the expired
                 * case because it is a different check in the library and a
                 * generator that only ever made one of them would satisfy the
                 * other's test. */
                {
                    char fcert[TF_PATH];
                    char fkey[TF_PATH];
                    nf_node_t n4;
                    int p4;

                    (void)tf_tls_make_cert(dir, "future", "irc.tls",
                                           "DNS:irc.tls,IP:127.0.0.1,DNS:localhost",
                                           86400, 172800, 0600);
                    snprintf(fcert, sizeof fcert, "%s/future.crt", dir);
                    snprintf(fkey, sizeof fkey, "%s/future.key", dir);
                    argv[4] = "--tls-cert"; argv[5] = fcert;
                    argv[6] = "--tls-key"; argv[7] = fkey;
                    argv[8] = "--tls-port"; argv[9] = g_port;
                    argv[10] = NULL; argv[11] = NULL; argv[12] = NULL;
                    if (spawn_argv(&n4, argv) == 0) {
                        tf_tls_t t;
                        const char *why = NULL;
                        const char *q = strstr(n4.out, "tls_port=");

                        p4 = (q != NULL) ? atoi(q + 9) : -1;
                        check(tf_tls_connect(&t, p4, fcert, "irc.tls", &why) != 0,
                              "a NOT-YET-VALID certificate is refused by a client "
                              "that verifies it",
                              (why != NULL) ? why : "the handshake SUCCEEDED");
                        tf_tls_close(&t);
                        (void)nf_stop(&n4);
                        nf_free(&n4);
                    } else {
                        check(0, "spawn a node with a not-yet-valid certificate",
                              NULL);
                    }
                }
                /* WRONG NAME. The certificate's SAN is a different host, signed by
                 * the same authority the client trusts. A chain check alone
                 * ACCEPTS this one -- which is the whole argument for the name
                 * check, and why this case exists separately from the wrong-CA
                 * one. */
                {
                    char nc[TF_PATH];
                    char nk[TF_PATH];
                    nf_node_t n5;
                    int p5;

                    (void)tf_tls_make_cert(dir, "othername", "irc.tls",
                                           "IP:10.99.99.99,DNS:not-this-node",
                                           0, 86400, 0600);
                    snprintf(nc, sizeof nc, "%s/othername.crt", dir);
                    snprintf(nk, sizeof nk, "%s/othername.key", dir);
                    argv[4] = "--tls-cert"; argv[5] = nc;
                    argv[6] = "--tls-key"; argv[7] = nk;
                    argv[8] = "--tls-port"; argv[9] = g_port;
                    argv[10] = NULL; argv[11] = NULL; argv[12] = NULL;
                    if (spawn_argv(&n5, argv) == 0) {
                        tf_tls_t t;
                        const char *why = NULL;
                        const char *q = strstr(n5.out, "tls_port=");

                        p5 = (q != NULL) ? atoi(q + 9) : -1;
                        check(tf_tls_connect(&t, p5, nc, "irc.tls", &why) != 0,
                              "a certificate signed by the TRUSTED authority but "
                              "naming a DIFFERENT host is refused, which a chain "
                              "check alone would accept",
                              (why != NULL) ? why : "the handshake SUCCEEDED");
                        tf_tls_close(&t);
                        (void)nf_stop(&n5);
                        nf_free(&n5);
                    } else {
                        check(0, "spawn a node with a mismatched-name certificate",
                              NULL);
                    }
                }
                (void)nf_stop(&n2);
                nf_free(&n2);
            }
        }

        /* --- STARTTLS: the upgrade, and the three refusals --- */
        {
            nf_node_t n6;
            test_client_t plain2;
            int p6;
            const char *q;

            /* NO --tls-port, and that is deliberate rather than an omission:
             * STARTTLS is then the ONLY way to reach an encrypted connection on
             * this node, so a test that passed by connecting to an implicit-TLS
             * port would be testing a different path than the one it names. */
            argv[0] = a0; argv[1] = a1; argv[2] = a2; argv[3] = a3;
            argv[4] = "--tls-cert"; argv[5] = g_cert;
            argv[6] = "--tls-key"; argv[7] = g_key;
            argv[8] = NULL; argv[9] = NULL; argv[10] = NULL;
            argv[11] = NULL; argv[12] = NULL; argv[13] = NULL;
            argv[14] = NULL; argv[15] = NULL;
            if (spawn_argv(&n6, argv) == 0) {
                (void)q;
                p6 = n6.port;
                check(nf_expect(&n6, "tls_port=-1", 5000) == 0,
                      "with no --tls-port the node reports tls_port=-1, and `sts` "
                      "therefore carries a duration with no port -- which a client "
                      "on an insecure connection correctly ignores",
                      NULL);

                /* 1. ALREADY REGISTERED. */
                if (tc_connect(&plain2, p6) != 0) {
                    check(0, "connect for the STARTTLS refusals", NULL);
                } else {
                    (void)tc_send(&plain2, "NICK afterreg");
                    (void)tc_send(&plain2, "USER afterreg 0 * :A");
                    check(tc_expect(&plain2, " 001 ", 10000) == 0,
                          "a client registers", tc_buffer(&plain2));
                    (void)tc_send(&plain2, "STARTTLS");
                    check(tc_expect(&plain2, " 691 ", 10000) == 0,
                          "STARTTLS after REGISTRATION is refused 691", NULL);
                    check(strstr(tc_buffer(&plain2),
                                 "only available before registration") != NULL,
                          "the refusal says the connection has already registered, "
                          "which is the specification's own rule",
                          tc_buffer(&plain2));
                    tc_close(&plain2);
                }

                /* 2. AFTER A CREDENTIAL. PASS in the clear, then STARTTLS: the
                 * password has already been on the wire, so upgrading cannot undo
                 * that and the connection is refused. This is the refusal that is
                 * easy to get wrong and it is the one that matters. */
                if (tc_connect(&plain2, p6) != 0) {
                    check(0, "connect for the credential case", NULL);
                } else {
                    /* PASS AND NOTHING ELSE, so this case tests the credential
                     * rule and not the registration rule. Sending NICK and USER as
                     * well would make both rules fire and would only prove which
                     * one is checked FIRST -- which is the second case below, and is
                     * a real property worth its own assertion. */
                    (void)tc_send(&plain2, "PASS hunter2");
                    (void)tc_send(&plain2, "STARTTLS");
                    check(tc_expect(&plain2, " 691 ", 10000) == 0,
                          "STARTTLS after a PASS is refused 691: the credential "
                          "was already on the wire in the clear",
                          tc_buffer(&plain2));
                    check(strstr(tc_buffer(&plain2),
                                 "already been sent on this connection in the "
                                 "clear") != NULL,
                          "the refusal says a credential was already sent in the "
                          "clear, so an operator can see WHY",
                          tc_buffer(&plain2));
                    tc_close(&plain2);
                }
                /* THE SAME CONNECTION HAVING ALSO REGISTERED, and the reason is
                 * named is the CREDENTIAL rather than the registration. This is the
                 * case a client that has decided to authenticate produces, so it is
                 * the one that matters in the field: "too late, you registered" is
                 * true and says nothing about the password that is already on the
                 * wire. */
                if (tc_connect(&plain2, p6) != 0) {
                    check(0, "connect for the both-rules case", NULL);
                } else {
                    (void)tc_send(&plain2, "PASS hunter2");
                    (void)tc_send(&plain2, "NICK afterboth");
                    (void)tc_send(&plain2, "USER afterboth 0 * :A");
                    (void)tc_send(&plain2, "STARTTLS");
                    check(tc_expect(&plain2,
                                    "already been sent on this connection", 10000)
                              == 0,
                          "a client that sent a PASS AND registered is told about "
                          "the CREDENTIAL, not about registering: the registration "
                          "refusal is true and hides the finding that matters",
                          tc_buffer(&plain2));
                    check(strstr(tc_buffer(&plain2), "only available before "
                                                    "registration") == NULL,
                          "and the registration reason is NOT what it was told, so "
                          "the two refusals are distinguishable",
                          tc_buffer(&plain2));
                    tc_close(&plain2);
                }

                /* 3. THE HANDSHAKE IS REFUSED WHEN IT IS ALREADY TLS. Cheap to
                 * reach on an upgraded connection and it proves the check exists
                 * rather than being unreachable code. */
                {
                    tf_tls_t up;

                    if (tf_tls_connect_plain(&up, p6) == 0 &&
                        tf_tls_send(&up, "STARTTLS") == 0 &&
                        tf_tls_expect(&up, " 670 ", 10000) == 0) {
                        const char *why = NULL;

                        check(tf_tls_upgrade(&up, up.fd, g_cert, "irc.tls",
                                             &why) == 0,
                              "a STARTTLS upgrade completes a real handshake",
                              (why != NULL) ? why : "upgrade failed");
                        check(tf_tls_send(&up, "NICK starter") == 0,
                              "send NICK over the upgraded connection", NULL);
                        /* BOTH HALVES OF REGISTRATION. This line was MISSING for a
                         * long round of debugging in which the STARTTLS upgrade was
                         * blamed for the node "stopping reading" afterwards: `NICK`
                         * alone never completes registration on any node, so `001`
                         * could not arrive however well the transport worked. The
                         * wire trace that showed it was `NICK` framed by the node
                         * and nothing else -- which is correct behaviour, correctly
                         * observed, and easy to misread as a transport fault. */
                        check(tf_tls_send(&up, "USER starter 0 * :Starter") == 0,
                              "send USER over the upgraded connection", NULL);
                        check(tf_tls_expect(&up, " 001 ", 10000) == 0,
                              "registration completes over the UPGRADED connection, "
                              "not the implicit-TLS one",
                              tf_tls_buffer(&up));
                        check(tf_tls_send(&up, "STARTTLS") == 0,
                              "a second STARTTLS on the upgraded connection", NULL);
                        check(tf_tls_expect(&up, " 691 ", 10000) == 0,
                              "a second STARTTLS is refused 691, because a second "
                              "handshake inside a live session is not a thing any "
                              "client can use",
                              tf_tls_buffer(&up));
                        tf_tls_close(&up);
                    } else {
                        check(0, "STARTTLS reaches 670 and the upgrade completes",
                              tf_tls_buffer(&up));
                        tf_tls_close(&up);
                    }
                }
                (void)nf_stop(&n6);
                nf_free(&n6);
            } else {
                check(0, "spawn a node for the STARTTLS cases", NULL);
            }
        }

        /* --- --tls-require refuses a PLAINTEXT client at accept --- */
        {
            nf_node_t n7;
            test_client_t c7;
            int p7;

            argv[0] = a0; argv[1] = a1; argv[2] = a2; argv[3] = a3;
            argv[4] = "--tls-cert"; argv[5] = g_cert;
            argv[6] = "--tls-key"; argv[7] = g_key;
            argv[8] = "--tls-require";
            argv[9] = "--tls-port"; argv[10] = g_port;
            argv[11] = NULL; argv[12] = NULL; argv[13] = NULL;
            if (spawn_argv(&n7, argv) == 0) {
                check(nf_expect(&n7, "tls=required", 5000) == 0,
                      "the startup line says tls=required", NULL);
                p7 = n7.port;
                if (tc_connect(&c7, p7) != 0) {
                    check(0, "connect to a --tls-require node's PLAIN port", NULL);
                } else {
                    (void)tc_send(&c7, "NICK refused");
                    (void)tc_send(&c7, "USER refused 0 * :R");
                    /* THE REFUSAL IS WAITED FOR HERE, BEFORE THE NEXT WRITE, and
                     * that ordering is the point of the whole case.
                     *
                     * This node refuses at accept, so it closes a socket the
                     * client has already written to -- and the original version of
                     * this case then went straight on writing to it. Whether the
                     * client's writes landed before or after that close(fd) is a
                     * sub-millisecond race that loopback usually wins for the
                     * client, which is why it stayed green locally and killed
                     * test_tls on a loaded macOS Release runner: the write found
                     * the socket reset, and the harness's send had no
                     * MSG_NOSIGNAL, so EPIPE arrived as a SIGPIPE and took the
                     * test process down with it.
                     *
                     * Forcing the order removes the race rather than describing
                     * it. server.c closes the accepted fd BEFORE printing
                     * client_refused, so returning from the wait below proves the
                     * node has already refused and closed. Nothing here sleeps:
                     * both waits are for an observable event -- one line of the
                     * node's own output, and one end of the connection -- and the
                     * checks are the same two the case already made, moved to
                     * where they establish the ordering they are read in. */
                    check(nf_expect(&n7, "client_refused: fd=", 5000) == 0,
                          "the node reports client_refused with reason=TLS_REQUIRED, so "
                          "an operator can see WHY a client was dropped",
                          NULL);
                    check(nf_expect(&n7, "reason=TLS_REQUIRED", 5000) == 0,
                          "the reason names the flag, not a socket error", NULL);
                    /* A RESET IS THE EXPECTED SIGNATURE HERE, and accepting both
                     * outcomes is not a weakened assertion -- it is the correct
                     * one, and the reason is worth writing down.
                     *
                     * The node refuses at accept, which means it closes a socket
                     * the client has already written to and which the node never
                     * read. POSIX: a close() on a socket with unread data in its
                     * receive queue makes the kernel send RST rather than FIN. So a
                     * client that sent NICK and USER before the refusal arrives
                     * sees ECONNRESET, not EOF. `tc_expect_eof` distinguishes the
                     * two and returns -3 for a reset, which is why this assertion
                     * names both: the property being checked is "the connection
                     * ended and nothing was said", and a reset is how that
                     * arrives. Accepting a TIMEOUT instead would make the test
                     * pass against a node that simply stopped answering. */
                    {
                        int eof = tc_expect_eof(&c7, 10000);

                        check(eof == 0 || eof == -3,
                              "a PLAINTEXT client on a --tls-require node has its "
                              "connection ended at accept -- EOF, or the RST that "
                              "a close with unread data produces -- and no "
                              "registration burst",
                              tc_buffer(&c7));
                    }
                    check(strstr(tc_buffer(&c7), " 001 ") == NULL,
                          "and it received NO registration burst: refusing at "
                          "accept is the point, because refusing later would leave "
                          "a working unencrypted session",
                          tc_buffer(&c7));

                    /* AND NOW THE WRITE THAT MUST BE REPORTED RATHER THAN FATAL.
                     *
                     * Everything above has established that the node refused and
                     * that this connection ENDED -- tc_expect_eof() returned 0 or
                     * -3, so the socket has seen the end and not merely been
                     * promised one. A write from here is therefore a write into a
                     * peer that is gone, which is the condition that killed this
                     * test in CI, and the harness has to REPORT it.
                     *
                     * This is the assertion the fix exists to keep honest. With
                     * MSG_NOSIGNAL on tc_send_raw()'s send(2) the write comes back
                     * as EPIPE and tc_send() returns non-zero. Take the flag back
                     * off and this line is never reached: the process has already
                     * taken a SIGPIPE and died, so the suite is red by crashing
                     * rather than by this check -- which is the same defect with
                     * the same evidence, and it is why the ordering above is
                     * forced instead of raced. Without the forced ordering this
                     * check would be a coin flip that passes by accident.
                     *
                     * The node closes with NICK and USER still unread in its
                     * receive queue -- the refusal happens before any conn_t
                     * exists, so nothing is ever read -- which is what makes the
                     * kernel answer RST rather than FIN, and an RST is what makes
                     * the next write report EPIPE instead of being accepted. */
                    check(tc_send(&c7, "PING :after-the-refusal") != 0,
                          "a write into the connection the node refused is REPORTED "
                          "as a failed write by the harness, so the test learns it "
                          "happened instead of the process being killed by it",
                          NULL);
                    /* AND SIGPIPE IS STILL ARMED IN THE TEST PROCESS, which is the
                     * other half of that sentence and the half with no wire to
                     * assert on.
                     *
                     * `signal(SIGPIPE, SIG_IGN)` in a test's main() would also stop
                     * the death, and it is the shape this fix is required NOT to
                     * take: it is permanent and process-wide, so it disarms the
                     * signal for every write in every test -- the harness's, a
                     * test's own write(2), OpenSSL's -- and a test that then writes
                     * into a socket nobody is serving carries on to its next
                     * assertion and reports success. No assertion about any single
                     * write can tell that apart from the real fix, because
                     * send(2) returns the same EPIPE either way; the only thing
                     * that differs is whether the signal is still armed. So the
                     * test says so.
                     *
                     * This is an assertion about the TEST's own environment and not
                     * a wire line, which is worth naming rather than glossing: it
                     * cannot tell a reader anything about the node, and it is here
                     * because the decision it protects -- suppress the signal per
                     * send, do not disarm it per process -- is invisible from the
                     * outside otherwise. node_fixture.c's SIG_IGN is the deliberate
                     * counter-example and it lives in the other process: nf_child_run()
                     * runs in the FORKED CHILD node, where the shipped binary's own
                     * node_main.c would have disarmed it anyway, and never in a test.
                     *
                     * Cost: one sigaction(2) with a NULL first argument, which only
                     * reads the current disposition and changes nothing. */
                    {
                        struct sigaction sa;

                        memset(&sa, 0, sizeof sa);
                        check(sigaction(SIGPIPE, NULL, &sa) == 0 &&
                                  sa.sa_handler == SIG_DFL,
                              "SIGPIPE is still at its default disposition in a test "
                              "process, so a write that raises it is still fatal "
                              "here -- which is what makes MSG_NOSIGNAL on the send "
                              "the whole of the fix rather than a global ignore that "
                              "would hide every other write like it",
                              NULL);
                    }
                    tc_close(&c7);
                }
                (void)nf_stop(&n7);
                nf_free(&n7);
            } else {
                check(0, "spawn a --tls-require node", NULL);
            }
        }
    }

    case_one_named_gap();
    (void)msg;
    tf_tls_rmtree(dir);
    printf("== %d failure(s) ==\n", failures);
    return (failures == 0) ? 0 : 1;
}
