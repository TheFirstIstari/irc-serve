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
#include <errno.h>
#include <fcntl.h>
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

/* IMPLEMENTED, and the reason it is here rather than stubbed is a coverage hole a
 * fault injection found.
 *
 * `tf_tls_write_file()` is plain POSIX -- open, write, fchmod -- and needs no crypto
 * at all, so it compiles and works in a build with no OpenSSL. It was stubbed out
 * here on the reasoning that "the only caller is the generator, which cannot run",
 * and that reasoning was wrong about what the TESTS do with it: tests/integration/
 * test_tls.c uses it to put a key file on disk with mode 0644 and mode 0640 so the
 * node can be asked to REFUSE it. With the stub, the default build's copy of that
 * test exited at the generator and asserted one thing -- so the world-readable-key
 * refusal, which is the single most important thing in this file, was asserted in
 * the TLS build only. The build that every CI runner compiles was the one that
 * checked least.
 *
 * So it is implemented here, and the fifteen lines are the same fifteen lines as in
 * tls_fixture.c because duplicating them is cheaper than a third source file in the
 * harness -- and because a stub that silently returns -1 for something that does
 * not need the thing it was stubbed for is the shape of bug this project has been
 * bitten by repeatedly. */
int tf_tls_write_file(const char *path, const void *data, size_t n,
                      unsigned mode)
{
    /* The fchmod() AFTER the open is the load-bearing half and the comment in
     * tls_fixture.c explains why: the mode argument to open() is modified by the
     * process umask, so asking for 0644 and getting 0644 depends on the runner.
     * O_TRUNC matters because the mode-change case reopens an existing file. */
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);

    if (fd < 0) {
        return -1;
    }
    if (fchmod(fd, (mode_t)mode) != 0) {
        (void)close(fd);
        return -1;
    }
    while (n > 0u) {
        ssize_t w = write(fd, data, n);

        if (w < 0) {
            if (errno == EINTR) {
                continue;
            }
            (void)close(fd);
            return -1;
        }
        data = (const char *)data + (size_t)w;
        n -= (size_t)w;
    }
    return close(fd);
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
        /* THE LENGTH IS CHECKED RATHER THAN TRUSTED, and the reason is gcc-16:
         * `snprintf(path, sizeof path, "%s/%s", dir, e->d_name)` is diagnosed as
         * a possible truncation because dir[] is 512 bytes, d_name can be a
         * NAME_MAX string, and nothing in the types says the sum fits path[].
         * It does (769 < 1024) and it always has, but "it does" is not something
         * a compiler can see and this project builds with -Werror on three
         * compilers.
         *
         * So the check is explicit: a name that would not fit is skipped rather
         * than truncated, because a TRUNCATED path here would unlink a file whose
         * name is not the one read. There is nothing left behind either way -- the
         * directory is under the build tree and per-process -- and skipping is
         * strictly safer than guessing. */
        {
            size_t dlen = strlen(dir);
            size_t nlen = strlen(e->d_name);

            if (dlen + 1u + nlen + 1u > sizeof path) {
                continue;
            }
            memcpy(path, dir, dlen);
            path[dlen] = '/';
            memcpy(path + dlen + 1u, e->d_name, nlen + 1u);
        }
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
