/* tls_fixture.c -- see tls_fixture.h. A real TLS client and a real certificate
 * generator, built on OpenSSL's API rather than by shelling out to the openssl(1)
 * binary.
 *
 * ---------------------------------------------------------------------------
 * WHY NOT `system("openssl req ...")`
 * ---------------------------------------------------------------------------
 * It is the obvious way and it was the first draft. Three reasons it is not:
 *
 *   1. IT IS A CTest SKIP IN DISGUISE. The openssl binary is not on PATH on every
 *      runner -- a minimal container image has libssl-dev and no openssl package --
 *      and a test that shells out to a missing binary has to either skip or fail,
 *      and this project has a skip ratchet whose entire point is that a test that
 *      cannot run must not count as a test. Building the certificate with the same
 *      library that will verify it needs nothing on PATH but the library the
 *      binary already links.
 *   2. PARSING. openssl req prints progress to stderr and its output format is
 *      not a stable interface. A test that greps it is a test that breaks when
 *      OpenSSL changes a warning.
 *   3. A SUBPROCESS PER CERTIFICATE, at ~100 ms each, in a suite run at -j8. Not
 *      fatal, and not worth it for something the API does in microseconds.
 *
 * The API route is more code and it is code the project controls: the validity
 * arithmetic the expired and not-yet-valid cases depend on is set explicitly with
 * X509_gmtime_adj rather than inherited from whatever -days the operator's clock
 * would have implied.
 */
#include "harness/tls_fixture.h"

#include <dirent.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include "harness/irc_client.h"
#include "tls_backend.h"

/* How often a deadline loop checks. A polling interval, never an assumption about
 * how long the other side takes -- the same rule tests/harness/irc_client.h gives
 * and for the same reason. */
#define TF_POLL_MS 20

/* Deadlines here are generous: they are for a forked child on a possibly loaded CI
 * machine, not estimates of how long anything should take. */
#define TF_HANDSHAKE_TIMEOUT_MS 15000
#define TF_IO_TIMEOUT_MS 15000

int tf_tls_available(void)
{
    return tls_backend_available();
}

/* ---------------------------------------------------------------------------
 * FILE HELPERS
 * --------------------------------------------------------------------------- */
/* Every path this file builds is `"<dir>/<stem><.suffix>"`, where dir is a
 * caller-supplied buffer. The destination is sized for the LONGEST such
 * composition rather than for a single component, because gcc-16 will not accept a
 * same-sized destination under -Werror while the two clang builds do not diagnose
 * it -- and three compilers disagreeing about whether a construct is a defect is a
 * situation to satisfy the strictest in rather than to suppress. */
#define TF_PATH_MAX 2048

int tf_tls_write_file(const char *path, const void *data, size_t n,
                      unsigned mode)
{
    /* open() with the mode in the call AND an explicit fchmod() afterwards, because
     * the mode argument to open() is MODIFIED BY THE PROCESS UMASK -- so
     * `open(path, O_CREAT, 0600)` under a umask of 022 produces 0600 anyway (umask
     * only removes bits) but `open(path, O_CREAT, 0666)` under umask 022 produces
     * 0644, which is exactly the case the world-readable-key refusal exists to
     * catch. Writing the key and then fchmod()ing it to what the caller asked for
     * makes the fixture's intent the file's actual state rather than a negotiation
     * with whatever umask the runner happens to have.
     *
     * O_TRUNC matters for the mode-change case: the file already exists with 0600
     * and reopening it without O_TRUNC would leave the OLD contents in place. */
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

/* ---------------------------------------------------------------------------
 * THE CERTIFICATE GENERATOR
 * --------------------------------------------------------------------------- */
/* Add one X.509v3 extension.
 *
 * `cert` and `issuer` are passed SEPARATELY and are the same pointer here, because
 * OpenSSL's extension context wants the issuer distinct from the subject even for
 * a self-signed certificate, and passing one name twice is what the API documents
 * for that case. Getting it wrong produces extensions that build but verify
 * nothing. */
static int add_ext(X509 *cert, X509 *issuer, int nid, const char *value)
{
    X509V3_CTX ctx;
    X509_EXTENSION *ex;

    /* X509V3_set_ctx_nodb IS A MACRO whose expansion is `ctx->db = NULL`, so there
     * is no expression here to cast or discard: a `(void)` in front of it is an
     * error ("expression is not assignable"), because void-casting an assignment
     * is not a thing C has. The macro has to be invoked, full stop. It is written
     * without a semicolon because the macro supplies one, and -Weverything counts
     * the resulting `NULL;` as an empty statement -- so the two lines below are the
     * only spelling that compiles, and they are ugly because the header is. */
    X509V3_set_ctx_nodb(&ctx)
    (void)X509V3_set_ctx(&ctx, issuer, cert, NULL, NULL, 0);
    ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
    if (ex == NULL) {
        return -1;
    }
    if (X509_add_ext(cert, ex, -1) != 1) {
        X509_EXTENSION_free(ex);
        return -1;
    }
    X509_EXTENSION_free(ex);
    return 0;
}

int tf_tls_make_cert(const char *dir, const char *stem, const char *cn,
                     const char *san, long not_before_offset,
                     long not_after_offset, unsigned key_mode)
{
    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;
    BIO *bio = NULL;
    char path[TF_PATH_MAX];
    int ok = -1;

    if (dir == NULL || stem == NULL || cn == NULL) {
        return -1;
    }
    /* A 2048-bit RSA key: the smallest size any current TLS client will accept,
     * and a generation cost small enough that a test generating four of them
     * does not notice. ECDSA would be faster to generate and every client here
     * speaks it, but RSA is what openssl(1) produces by default and matching the
     * obvious tool keeps the fixture readable to somebody comparing it against a
     * command line. */
    pkey = EVP_RSA_gen(2048);
    if (pkey == NULL) {
        goto done;
    }
    cert = X509_new();
    if (cert == NULL) {
        goto done;
    }
    /* SERIAL. 1 is fine and is what openssl req -set_serial does for a
     * throwaway; nothing in this project reads it and nothing verifies it. */
    if (X509_set_version(cert, 2) != 1) {
        goto done;
    }
    if (ASN1_INTEGER_set(X509_get_serialNumber(cert), 1) != 1) {
        goto done;
    }
    if (X509_gmtime_adj(X509_getm_notBefore(cert), not_before_offset) == NULL) {
        goto done;
    }
    if (X509_gmtime_adj(X509_getm_notAfter(cert), not_after_offset) == NULL) {
        goto done;
    }
    if (X509_set_pubkey(cert, pkey) != 1) {
        goto done;
    }
    {
        /* THE NAME IS BUILT SEPARATELY AND THEN ASSIGNED, rather than reached
         * through X509_get_subject_name() and edited in place.
         *
         * X509_get_subject_name() returns `const X509_NAME *` in OpenSSL 4, and
         * X509_NAME_add_entry_by_txt() needs a mutable one -- so the in-place
         * shape this file used first does not compile against the library this
         * project links. Building it separately is also the more honest shape: it
         * says the name is this fixture's construction rather than something read
         * out of the certificate and modified, and it lets subject and issuer be
         * set from ONE name, which is what "self-signed" means and what would
         * otherwise be two easily-diverged copies.
         *
         * A generated certificate IS its own trust anchor (basicConstraints
         * CA:TRUE below), so the same file serves as the leaf and as the --tls-ca
         * a test points at it. The tests that need two DIFFERENT authorities
         * generate two of these and verify one against the other. */
        X509_NAME *name = X509_NAME_new();

        if (name == NULL) {
            goto done;
        }
        if (X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                       (const unsigned char *)cn, -1, -1, 0) != 1) {
            X509_NAME_free(name);
            goto done;
        }
        if (X509_set_subject_name(cert, name) != 1 ||
            X509_set_issuer_name(cert, name) != 1) {
            X509_NAME_free(name);
            goto done;
        }
        X509_NAME_free(name);
    }
    if (san != NULL && add_ext(cert, cert, NID_subject_alt_name, san) != 0) {
        goto done;
    }
    /* basicConstraints CA:TRUE, so the same file can serve as its own --tls-ca.
     * Without it OpenSSL will not accept a self-signed certificate as an anchor,
     * which would make the fixture's certificates unusable as trust roots and the
     * whole "one self-signed cert is both the leaf and the CA" shape would not
     * work. */
    if (add_ext(cert, cert, NID_basic_constraints, "critical,CA:TRUE") != 0) {
        goto done;
    }
    if (X509_sign(cert, pkey, EVP_sha256()) == 0) {
        goto done;
    }

    snprintf(path, sizeof path, "%s/%s.crt", dir, stem);
    bio = BIO_new_file(path, "w");
    if (bio == NULL) {
        goto done;
    }
    if (PEM_write_bio_X509(bio, cert) != 1) {
        goto done;
    }
    BIO_free(bio);
    bio = NULL;

    /* THE KEY, and the mode is the point of this fixture for one of the required
     * cases. The buffer is written through a BIO so the on-disk bytes are exactly
     * what OpenSSL would have written, rather than a re-serialisation. */
    snprintf(path, sizeof path, "%s/%s.key", dir, stem);
    bio = BIO_new_file(path, "w");
    if (bio == NULL) {
        goto done;
    }
    if (PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL) != 1) {
        goto done;
    }
    BIO_free(bio);
    bio = NULL;
    /* chmod() rather than tf_tls_write_file(), and the reason is that this helper
     * TRUNCATES: rewriting the key through it with an empty payload would leave a
     * zero-byte private key and every "wrong CA" or "expired" case would then be
     * testing OpenSSL's complaint about an empty file instead. The mode is applied
     * to what is already on disk.
     *
     * AND THE MODE IS A TEST INPUT, not tidiness: the world-readable-key refusal
     * needs a key whose mode is 0644, and this is where that happens. */
    if (chmod(path, (mode_t)key_mode) != 0) {
        goto done;
    }
    ok = 0;

done:
    if (bio != NULL) {
        BIO_free(bio);
    }
    if (cert != NULL) {
        X509_free(cert);
    }
    if (pkey != NULL) {
        EVP_PKEY_free(pkey);
    }
    if (ok != 0) {
        ERR_clear_error();
    }
    return ok;
}

/* ---------------------------------------------------------------------------
 * THE TLS CLIENT
 * --------------------------------------------------------------------------- */
void tf_tls_init(tf_tls_t *t)
{
    if (t == NULL) {
        return;
    }
    memset(t, 0, sizeof *t);
    t->fd = -1;
}

static int buf_append(tf_tls_t *t, const char *data, size_t n)
{
    if (t->len + n + 1u > t->cap) {
        size_t want = (t->cap == 0u) ? 4096u : t->cap;
        char *grown;

        while (t->len + n + 1u > want) {
            want *= 2u;
        }
        grown = (char *)realloc(t->buf, want);
        if (grown == NULL) {
            return -1;
        }
        t->buf = grown;
        t->cap = want;
    }
    memcpy(t->buf + t->len, data, n);
    t->len += n;
    t->buf[t->len] = '\0';
    return 0;
}

static int raw_connect(int port)
{
    struct sockaddr_in addr;
    int fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd < 0) {
        return -1;
    }
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons((unsigned short)port);
    if (connect(fd, (struct sockaddr *)&addr, sizeof addr) != 0) {
        (void)close(fd);
        return -1;
    }
    /* BLOCKING FOR THE HANDSHAKE, and nonblocking afterwards. That is not
     * indecision, it is the only correct split, and the first version of this
     * function was blocking throughout and HUNG.
     *
     * A TLS RECORD boundary is not an application-data boundary: one record can
     * carry half a line, and OpenSSL will not hand back a partial application
     * message. So `tf_tls_expect()` does select(), sees the socket readable, calls
     * SSL_read() -- and SSL_read blocks, because it wants the rest of the record
     * and select() said nothing about that. A blocking socket plus a
     * record-oriented API plus a select() loop is a hang, and it hung: the test
     * stopped at the first line after the STARTTLS upgrade and sat in
     * ssl3_read_bytes until the harness killed it.
     *
     * The HANDSHAKE is several round trips of exact byte counts, so leaving the
     * socket blocking for it is both safe and simpler -- SSL_connect() needs no
     * readiness machinery to drive it. Afterwards the socket goes nonblocking and
     * SSL_read()'s WANT_READ is answered the way the node answers it: by coming
     * back to the loop. That is not reimplementing the server's transport; it is
     * one fcntl() and one error branch. */
    return fd;
}

int tf_tls_connect_plain(tf_tls_t *t, int port)
{
    if (t == NULL) {
        return -1;
    }
    tf_tls_init(t);
    t->fd = raw_connect(port);
    return (t->fd < 0) ? -1 : 0;
}

static SSL_CTX *client_ctx(const char *cafile)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());

    if (ctx == NULL) {
        return NULL;
    }
    /* Verification is ON in this client too, for the same reason the node's is:
     * a test that accepted anything could not assert that the node refuses
     * something. `cafile == NULL` means the system roots, which is a legitimate
     * configuration to test against -- a self-signed certificate fails it. */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    if (cafile != NULL && cafile[0] != '\0') {
        if (SSL_CTX_load_verify_locations(ctx, cafile, NULL) != 1) {
            SSL_CTX_free(ctx);
            return NULL;
        }
    } else {
        if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
            SSL_CTX_free(ctx);
            return NULL;
        }
    }
    return ctx;
}

static uint64_t tf_now_ms(void);

static int do_handshake(tf_tls_t *t, int fd, const char *cafile, const char *sni,
                        const char **why)
{
    SSL_CTX *ctx = client_ctx(cafile);
    SSL *ssl;

    if (why != NULL) {
        *why = NULL;
    }
    if (ctx == NULL) {
        if (why != NULL) {
            *why = "context";
        }
        return -1;
    }
    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        SSL_CTX_free(ctx);
        if (why != NULL) {
            *why = "SSL_new";
        }
        return -1;
    }
    /* SNI AND THE NAME CHECK, and they are the same string for the same reason.
     *
     * Sending SNI without asking OpenSSL to VERIFY that name is a client that
     * proves it is talking to the right server and then does not check -- which is
     * how a certificate for `not-this-node`, signed by a CA the client trusts, gets
     * accepted. The wrong-NAME test case exists precisely to catch that, and it
     * caught this fixture instead of the node the first time it ran: the client set
     * SNI and no verification parameter, so the handshake succeeded against a
     * certificate naming a different host and the assertion failed for the wrong
     * reason.
     *
     * The name checked is `sni` rather than the address the socket connected to,
     * because a test connecting to 127.0.0.1 wants to check the node's NAME -- which
     * is what a real client connecting to `irc.example.com` checks, and what the
     * node's own peer-link path does. Checking the loopback address would make the
     * wrong-name case untestable without issuing certificates for 127.0.0.2.
     */
    if (sni != NULL && sni[0] != '\0') {
        char mutable_sni[256];
        X509_VERIFY_PARAM *param;

        /* The COPY is not a style choice: SSL_set_tlsext_host_name casts its
         * argument away from const, and -Wcast-qual is in this project's warning
         * set. tls_openssl.c has the same shape and the same reason; see there. */
        if (strlen(sni) >= sizeof mutable_sni) {
            if (why != NULL) {
                *why = "sni_too_long";
            }
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            return -1;
        }
        memcpy(mutable_sni, sni, strlen(sni) + 1u);
        (void)SSL_set_tlsext_host_name(ssl, mutable_sni);
        param = SSL_get0_param(ssl);
        if (X509_VERIFY_PARAM_set1_host(param, sni, 0) != 1) {
            if (why != NULL) {
                *why = "cannot_set_verify_host";
            }
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            return -1;
        }
    }
    if (SSL_set_fd(ssl, fd) != 1) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        if (why != NULL) {
            *why = "SSL_set_fd";
        }
        return -1;
    }
    SSL_set_connect_state(ssl);
    if (SSL_connect(ssl) != 1) {
        unsigned long e = ERR_peek_last_error();

        if (why != NULL) {
            *why = (ERR_reason_error_string(e) != NULL) ? ERR_reason_error_string(e)
                                                        : "handshake";
        }
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return -1;
    }
    /* The CONTEXT IS FREED HERE AND THE SSL SURVIVES, which is not a mistake.
     * SSL_new() takes a reference on its context, so the session stays valid after
     * the context is released -- and releasing it means this client's trust store
     * (which may be a temporary directory's certificate) is not pinned in memory for
     * the life of the test. */
    /* AND THAT IS THE WHOLE OF THE POST-HANDSHAKE STORY: NOTHING.
     *
     * There is a version of this fixture that drains post-handshake records
     * (a TLS 1.3 server sends NewSessionTicket once the handshake completes) by
     * looping SSL_read() until it reports nothing available. It was written, and it
     * was wrong twice over:
     *
     *   it SPUN for its whole deadline, because a nonblocking SSL_read() that has
     *   consumed a record and wants the next one answers WANT_READ -- which is not
     *   "nothing available", it is "nothing available RIGHT NOW", and a loop that
     *   treats it as a reason to try again with no readiness wait in it burns 500
     *   milliseconds per handshake doing nothing;
     *
     *   and it DISCARDED anything it read, into a scratch buffer, which is a data
     *   loss in a fixture whose whole job is to show a reader what the node said.
     *
     * Neither is needed, because tf_tls_expect() already answers WANT_READ by going
     * back to select(), and a post-handshake record produces exactly WANT_READ: the
     * node's NewSessionTicket is consumed, no application message results, and the
     * next select() waits for real data. Post-handshake records are OpenSSL's
     * problem and it handles them.
     *
     * The time this cost is worth recording, because the failure it caused was
     * attributed to the node for a whole round of debugging: with the drain loop
     * spinning, the STARTTLS case in test_tls.c looked like a node that accepted an
     * upgrade and then stopped reading. The node was fine. The test had not sent
     * USER. */
    SSL_CTX_free(ctx);
    t->ssl = ssl;
    t->fd = fd;
    t->secure = 1;
    return 0;
}

int tf_tls_connect(tf_tls_t *t, int port, const char *cafile, const char *sni,
                   const char **why)
{
    int fd;

    if (t == NULL) {
        return -1;
    }
    tf_tls_init(t);
    fd = raw_connect(port);
    if (fd < 0) {
        if (why != NULL) {
            *why = "connect";
        }
        return -1;
    }
    return do_handshake(t, fd, cafile, sni, why);
}

int tf_tls_upgrade(tf_tls_t *t, int fd, const char *cafile, const char *sni,
                   const char **why)
{
    if (t == NULL || fd < 0) {
        return -1;
    }
    t->fd = fd;
    return do_handshake(t, fd, cafile, sni, why);
}

int tf_tls_send(tf_tls_t *t, const char *line)
{
    char buf[1024];
    int n;
    int sent = 0;

    if (t == NULL || line == NULL) {
        return -1;
    }
    n = snprintf(buf, sizeof buf, "%s\r\n", line);
    if (n < 0 || (size_t)n >= sizeof buf) {
        return -1;
    }
    while (sent < n) {
        int w;

        if (t->ssl != NULL) {
            w = SSL_write((SSL *)t->ssl, buf + sent, n - sent);
        } else {
            w = (int)send(t->fd, buf + sent, (size_t)(n - sent), 0);
        }
        if (w > 0) {
            sent += w;
            continue;
        }
        return -1;
    }
    return 0;
}

static uint64_t tf_now_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000L);
}

int tf_tls_expect(tf_tls_t *t, const char *needle, int timeout_ms)
{
    uint64_t deadline;

    if (t == NULL || needle == NULL || t->fd < 0) {
        return -1;
    }
    if (t->buf != NULL && strstr(t->buf, needle) != NULL) {
        return 0;
    }
    deadline = tf_now_ms() + (uint64_t)timeout_ms;
    for (;;) {
        struct timeval tv;
        fd_set rd;
        int rc;

        if (t->buf != NULL && strstr(t->buf, needle) != NULL) {
            return 0;
        }
        FD_ZERO(&rd);
        FD_SET(t->fd, &rd);
        tv.tv_sec = 0;
        tv.tv_usec = TF_POLL_MS * 1000;
        rc = select(t->fd + 1, &rd, NULL, NULL, &tv);
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        /* THE PARENT KEEPS READING, once per iteration. See tc_pump()'s comment:
         * this loop cannot use tc_expect(), so it has to drive the same hook
         * itself or a child whose stdout pipe fills up will wedge inside its own
         * event loop and answer nobody. */
        tc_pump();
        if (rc > 0) {
            char chunk[4096];
            int n;

            if (t->ssl != NULL) {
                n = SSL_read((SSL *)t->ssl, chunk, (int)sizeof chunk);
                if (n <= 0) {
                    int err = SSL_get_error((SSL *)t->ssl, n);

                    /* WANT_READ IS NOT AN ENDING. It means OpenSSL consumed what
                     * was there and needs more of the same record before it can
                     * produce an application message -- the record-boundary
                     * problem raw_connect()'s comment describes. Treating it as a
                     * close would truncate every line that arrived split across two
                     * TLS records, which is most of them: the node writes 001-005
                     * and a MOTD as separate records.
                     *
                     * WANT_WRITE on a read means OpenSSL wants to renegotiate or
                     * send a key update, which needs a socket write this test never
                     * does. Treating it as "nothing right now" is the safe answer:
                     * the wait simply keeps polling. */
                    if (err == SSL_ERROR_WANT_READ ||
                        err == SSL_ERROR_WANT_WRITE) {
                        continue;
                    }
                    /* Anything else is a real close (close_notify, an EOF, or a
                     * protocol error) and there is nothing more coming. */
                    return -1;
                }
            } else {
                n = (int)recv(t->fd, chunk, sizeof chunk, 0);
            }
            if (n > 0) {
                if (buf_append(t, chunk, (size_t)n) != 0) {
                    return -1;
                }
                continue; /* re-check before waiting again */
            }
            return -1;
        }
        if (tf_now_ms() >= deadline) {
            return -1;
        }
    }
}

const char *tf_tls_buffer(const tf_tls_t *t)
{
    if (t == NULL || t->buf == NULL) {
        return "";
    }
    return t->buf;
}

void tf_tls_close(tf_tls_t *t)
{
    if (t == NULL) {
        return;
    }
    if (t->ssl != NULL) {
        (void)SSL_shutdown((SSL *)t->ssl);
        SSL_free((SSL *)t->ssl);
        t->ssl = NULL;
    }
    if (t->fd >= 0) {
        (void)close(t->fd);
        t->fd = -1;
    }
    free(t->buf);
    t->buf = NULL;
    t->len = 0;
    t->cap = 0;
    t->secure = 0;
}
