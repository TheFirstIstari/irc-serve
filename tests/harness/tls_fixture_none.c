/* tls_fixture_none.c -- the TLS test fixture's stub for a build WITHOUT TLS.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS FILE EXISTS RATHER THAN COMPILING tls_fixture.c UNCONDITIONALLY
 * ---------------------------------------------------------------------------
 * tls_fixture.c includes <openssl/ssl.h> and calls into libssl. A default build
 * has neither, which is the whole point of `-DWITH_TLS=OFF`: no OpenSSL headers on
 * the include path and no OpenSSL in the link line. So the fixture is selected the
 * same way irc_core's backend is -- one file or the other, chosen by the build
 * option -- rather than being conditionally compiled with #if, which would put the
 * build option into the test tree as well as the library's.
 *
 * The first version of tests/integration/test_tls.c simply called the real
 * fixture unconditionally and did not link in a default build at all. The symptom
 * was a link error naming tf_tls_upgrade, which is exactly the "the fault did not
 * compile" shape this project has been bitten by repeatedly -- except that here it
 * was a FEATURE not compiling, and the honest fix is the same: make the build
 * honest rather than assume it.
 *
 * ---------------------------------------------------------------------------
 * AND WHAT THIS MEANS FOR THE TEST, which is the part that matters
 * ---------------------------------------------------------------------------
 * NOTHING IS SKIPPED. tests/integration/test_tls.c asks tf_tls_available() at
 * runtime -- which routes here and answers 0 -- and asserts, in the default build:
 *
 *   - no `tls` and no `sts` in CAP LS
 *   - STARTTLS answered 691 with a reason naming TLS being unavailable
 *   - --tls-port without a certificate refused
 *   - --tls-cert without --tls-key refused
 *   - a group- or world-readable private key refused
 *
 * Those are the assertions that matter most for the configuration this project
 * ships by default, because the default build is the one every CI runner compiles
 * and the one 83 other tests run against. Returning CTest's skip code here instead
 * would assert NOTHING on the default build and would make the skip ratchet
 * describe a test that does not exist.
 *
 * The generation stub returns -1 rather than pretending, and test_tls.c treats that
 * as the assertion "certificate generation is possible exactly when TLS is
 * compiled in" -- which is true, and is worth stating because it is what makes the
 * two branches equivalent rather than one of them vacuous.
 */
#include "harness/tls_fixture.h"

#include <dirent.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "tls_backend.h"

int tf_tls_available(void)
{
    /* THE SAME QUESTION irc_core's own stub answers. It is not `0` written here:
     * it is the backend's own answer, so a build that somehow compiled this file
     * WITH a TLS backend would report TLS available rather than reporting a
     * fixture that cannot possibly work. */
    return tls_backend_available();
}

int tf_tls_make_cert(const char *dir, const char *stem, const char *cn,
                     const char *san, long not_before_offset,
                     long not_after_offset, unsigned key_mode)
{
    (void)dir;
    (void)stem;
    (void)cn;
    (void)san;
    (void)not_before_offset;
    (void)not_after_offset;
    (void)key_mode;
    return -1;
}

int tf_tls_write_file(const char *path, const void *data, size_t n,
                      unsigned mode)
{
    /* NOT REIMPLEMENTED HERE, and that is a real gap in this stub rather than an
     * oversight to be papered over: it has no caller on a default build, because the
     * only user is the generator above, which cannot run. Reimplementing fifteen
     * lines of open/write/chmod to serve a function nothing calls would be a second
     * thing to keep correct for no reader. A caller that needed it in this build
     * would get -1 and a test failure, which is the honest outcome. */
    (void)path;
    (void)data;
    (void)n;
    (void)mode;
    return -1;
}

void tf_tls_rmtree(const char *dir)
{
    /* IMPLEMENTED, not stubbed, because the test calls it UNCONDITIONALLY at the
     * end of every run -- including a run where a certificate WAS generated and a
     * node was started. A default-build run generates nothing, so this has nothing
     * to do, and a run that failed halfway may have left a node holding a socket;
     * cleaning up is the part that must work in both builds.
     *
     * It is duplicated from tls_fixture.c rather than moved to a shared file
     * because the alternative is a third source file in the harness for fifteen
     * lines of readdir/unlink, and this project's own convention -- test_util.c's
     * comment on why the assertion macros are macros rather than functions -- is
     * that a thing with exactly one reader is better written where it is read. */
    DIR *d = opendir(dir);
    struct dirent *e;

    if (d == NULL) {
        return;
    }
    while ((e = readdir(d)) != NULL) {
        char path[1024];

        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) {
            continue;
        }
        snprintf(path, sizeof path, "%s/%s", dir, e->d_name);
        (void)unlink(path);
    }
    (void)closedir(d);
}

void tf_tls_init(tf_tls_t *t)
{
    if (t != NULL) {
        memset(t, 0, sizeof *t);
        t->fd = -1;
    }
}

int tf_tls_connect(tf_tls_t *t, int port, const char *cafile, const char *sni,
                   const char **why)
{
    (void)t;
    (void)port;
    (void)cafile;
    (void)sni;
    if (why != NULL) {
        *why = "TLS_NOT_COMPILED_IN";
    }
    return -1;
}

int tf_tls_upgrade(tf_tls_t *t, int fd, const char *cafile, const char *sni,
                   const char **why)
{
    (void)t;
    (void)fd;
    (void)cafile;
    (void)sni;
    if (why != NULL) {
        *why = "TLS_NOT_COMPILED_IN";
    }
    return -1;
}

int tf_tls_connect_plain(tf_tls_t *t, int port)
{
    (void)t;
    (void)port;
    return -1;
}

int tf_tls_send(tf_tls_t *t, const char *line)
{
    (void)t;
    (void)line;
    return -1;
}

int tf_tls_expect(tf_tls_t *t, const char *needle, int timeout_ms)
{
    (void)t;
    (void)needle;
    (void)timeout_ms;
    return -1;
}

const char *tf_tls_buffer(const tf_tls_t *t)
{
    (void)t;
    return "";
}

void tf_tls_close(tf_tls_t *t)
{
    (void)t;
}
