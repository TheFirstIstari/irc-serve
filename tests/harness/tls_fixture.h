/* tls_fixture.h -- a REAL TLS client and a REAL certificate generator, for the
 * Phase 12 tests.
 *
 * ===========================================================================
 * WHY THE TESTS BRING THEIR OWN CLIENT
 * ===========================================================================
 * `openssl s_client` is an IMPLICIT-TLS client: it begins a handshake the moment
 * the TCP connection is up. It has no STARTTLS mode, because STARTTLS is an IRC
 * command rather than a protocol any other implementation speaks. So the
 * implicit-TLS path is driven with `openssl s_client` from the shell (see the
 * phase report and the gate), and every case that has to control the upgrade --
 * STARTTLS itself, a refused handshake, a certificate that must be rejected --
 * needs a client this project owns.
 *
 * It is not a mock. It links OpenSSL (irc_core exposes OpenSSL::SSL PUBLIC under
 * WITH_TLS, which is the one reason that linkage is PUBLIC rather than PRIVATE)
 * and it performs real handshakes against a real node over a real socket. What it
 * is instead of `openssl s_client` is a client whose plaintext phase is
 * controllable.
 *
 * ===========================================================================
 * WHY CERTIFICATES ARE GENERATED AND NEVER COMMITTED
 * ===========================================================================
 * A test that needs a certificate must GENERATE one, at run time, into a
 * temporary directory, and there are three reasons that is not merely tidy:
 *
 *   1. A COMMITTED PRIVATE KEY IS A LEAK THAT DOES NOT EXPIRE. This project
 *      refuses a group- or world-readable key as a security boundary, and
 *      committing a 0600 key with mode 600 in the repository would be a key whose
 *      safety depended on the checkout's umask and on every mirror's. Any key in
 *      git history is public forever.
 *   2. A COMMITTED CERTIFICATE HAS A FIXED VALIDITY WINDOW, and one of the
 *      required cases is that an EXPIRED certificate is REFUSED. A committed
 *      certificate would make that test either permanently failing or permanently
 *      skipped -- and this project has a skip ratchet precisely because a test
 *      that stops testing is worse than no test.
 *   3. A NOT-YET-VALID CERTIFICATE CANNOT BE COMMITTED AT ALL. It is invalid by
 *      construction until a future date arrives.
 *
 * So nothing key-shaped is in the repository, and the fixtures below write both
 * files with `tf_tls_write_private()`'s mode.
 *
 * ---------------------------------------------------------------------------
 * WHAT IS GENERATED, and why each shape is needed
 * ---------------------------------------------------------------------------
 *   one CA + one leaf     the happy path, and what `--tls-ca` verifies against.
 *   a SECOND, UNRELATED CA the "wrong CA is refused" case. The two share nothing:
 *                          not a key, not a name, not a signature.
 *   a leaf with notAfter in the past        the expired case.
 *   a leaf with notBefore in the future     the not-yet-valid case.
 *   a leaf whose SAN is a DIFFERENT name     the name-mismatch case. Chain
 *                          verification alone would accept this one, which is
 *                          exactly why tls_openssl.c checks the name.
 */
#ifndef TEST_HARNESS_TLS_FIXTURE_H
#define TEST_HARNESS_TLS_FIXTURE_H

#include <stddef.h>
#include <stdio.h>

#include "harness/irc_client.h"

/* ---------------------------------------------------------------------------
 * Is TLS compiled into irc_core? A RUNTIME question and deliberately not a
 * preprocessor one, so that a test can branch on the BUILD it is in rather than
 * being compiled out of it.
 * --------------------------------------------------------------------------- */
int tf_tls_available(void);

/* ---------------------------------------------------------------------------
 * GENERATE A SELF-SIGNED CERTIFICATE AND ITS KEY into `dir`.
 *
 *   dir   a directory that already exists (the tests use one under the build tree)
 *   stem  the file-name base; writes `<stem>.crt` and `<stem>.key`
 *   cn    the subject common name
 *   san   the subjectAltName extension's value, e.g. "DNS:localhost,IP:127.0.0.1",
 *         or NULL for none
 *   not_before_offset  seconds from NOW. 0 is "now"; a positive value is a
 *         NOT-YET-VALID certificate.
 *   not_after_offset   seconds from NOW. A negative value is an EXPIRED one.
 *   key_mode           the permissions to leave the key with -- 0600 normally,
 *         and 0644 for the case that tests this project's refusal of a key a
 *         group or other can read.
 *
 * Returns 0 on success. Both files are written even when the caller wants one of
 * them to be wrong: the refusal tests are about what the NODE does with a file, so
 * the file has to exist.
 *
 * WHY THE OFFSETS RATHER THAN THREE SEPARATE FUNCTIONS: "expired" and
 * "not yet valid" are the same certificate with different validity arithmetic, and
 * one generator is one thing to get right. A generator that took a flag would have
 * a flag that could be set wrongly and produce a certificate that was valid and
 * quietly satisfied nothing.
 * --------------------------------------------------------------------------- */
int tf_tls_make_cert(const char *dir, const char *stem, const char *cn,
                     const char *san, long not_before_offset,
                     long not_after_offset, unsigned key_mode);

/* Write `n` bytes to `path` with exactly `mode`. Used by the fixture's own
 * cleanup-free helpers and exposed because the world-readable-key case has to be
 * able to CHANGE a key's mode after the fact, which is what an operator's
 * umask would have done. */
int tf_tls_write_file(const char *path, const void *data, size_t n,
                      unsigned mode);

/* Remove a directory's contents recursively, best effort. Called at the end of a
 * test so a failed run does not leave keys in the build tree. Never fails the
 * test: a leftover temporary file is not a finding. */
void tf_tls_rmtree(const char *dir);

/* ---------------------------------------------------------------------------
 * A TLS CLIENT. Two entry points because there are two ways in.
 * --------------------------------------------------------------------------- */
typedef struct {
    int    fd;
    void  *ssl;      /* SSL*, hidden so this header needs no OpenSSL include */
    char  *buf;      /* accumulated PLAINTEXT, like test_client_t's */
    size_t len;
    size_t cap;
    int    secure;   /* 1 once a handshake has completed */
} tf_tls_t;

/* Prepare an unconnected client, the way tc_init() does. */
void tf_tls_init(tf_tls_t *t);

/* Connect and complete an IMPLICIT-TLS handshake to 127.0.0.1:`port`.
 *
 *   cafile  a PEM to verify the server's certificate against, or NULL to verify
 *           against the SYSTEM roots (which will fail for a self-signed test
 *           certificate, and that failure is a legitimate use: it is how the
 *           "wrong CA is refused" case is driven from the client side as well).
 *   sni     the server name for SNI, or NULL.
 *
 * Returns 0 on success. A REFUSED handshake returns -1 with `*why` (when `why` is
 * non-NULL) set to a short reason string from OpenSSL -- the tests assert on
 * refusal, so the reason has to be reachable rather than a bare failure. */
int tf_tls_connect(tf_tls_t *t, int port, const char *cafile, const char *sni,
                   const char **why);

/* Complete a handshake on an ALREADY-PLAINTEXT connection: the STARTTLS path.
 * `fd` must be a connected blocking socket. Returns 0 on success, -1 on refusal
 * with `*why` set. */
int tf_tls_upgrade(tf_tls_t *t, int fd, const char *cafile, const char *sni,
                   const char **why);

/* Connect a PLAINTEXT socket to 127.0.0.1:`port` without any handshake. Used by the
 * STARTTLS case, which has to speak IRC in the clear first. */
int tf_tls_connect_plain(tf_tls_t *t, int port);

/* Send `line` with CRLF. Returns 0 on success, -1 on failure. */
int tf_tls_send(tf_tls_t *t, const char *line);

/* Wait until `needle` appears in the accumulated PLAINTEXT, or the deadline
 * passes. Returns 0 on success, -1 on timeout.
 *
 * IT CANNOT BE tc_expect() and the reason is the whole reason this struct exists:
 * after a handshake the decrypted bytes are inside OpenSSL, not in the socket, so
 * reading the descriptor would return the NEXT record and never the one the client
 * is waiting for. A test that used tc_expect() after an upgrade would time out on
 * a node that answered perfectly. */
int tf_tls_expect(tf_tls_t *t, const char *needle, int timeout_ms);

/* Everything received so far, NUL-terminated. Do not modify. */
const char *tf_tls_buffer(const tf_tls_t *t);

/* Close and release. Sends close_notify, then closes the descriptor. Safe on a
 * zeroed or already-closed struct. */
void tf_tls_close(tf_tls_t *t);

#endif /* TEST_HARNESS_TLS_FIXTURE_H */
