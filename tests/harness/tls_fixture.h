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

/* ---------------------------------------------------------------------------
 * THE SAME GENERATOR, WITH AN ISSUER, because revocation needs one
 * ---------------------------------------------------------------------------
 * tf_tls_make_cert() makes a SELF-SIGNED CA:TRUE certificate, which is what every
 * Phase 12 case uses and which is deliberately unchanged: two nodes that trust each
 * other's certificate directly have no issuer, so there is nobody who could have
 * issued a revocation status for either of them.
 *
 * These two are the shapes a revocation check needs. tf_tls_make_ca() is the
 * self-signed authority (the same bytes tf_tls_make_cert() produces, named
 * separately so a reader of a revocation test can see which file is the CA).
 * tf_tls_make_issued() is a leaf whose ISSUER is another stem in the same
 * directory, and it writes leaf + issuer into `<stem>.crt` -- one file, because
 * --tls-cert takes a chain and a node presenting a bare leaf leaves its peer with no
 * issuer at all.
 *
 * Returns 0 on success; -1 on any failure, with OpenSSL's error queue cleared.
 * --------------------------------------------------------------------------- */
int tf_tls_make_ca(const char *dir, const char *stem, const char *cn,
                   long not_before_offset, long not_after_offset);

int tf_tls_make_issued(const char *dir, const char *stem, const char *cn,
                       const char *san, const char *issuer_stem,
                       long not_before_offset, long not_after_offset);

/* ---------------------------------------------------------------------------
 * A REAL OCSP RESPONSE, written as DER to `<stem>.ocsp`
 * ---------------------------------------------------------------------------
 *   issuer_stem    whose certificate and key build the CertID AND, by default, sign
 *                  the response -- which is what a real issuer does;
 *   subject_stem   the certificate the status is ABOUT;
 *   signer_stem    whose key signs it. NULL, or equal to issuer_stem, means the
 *                  issuer. A DIFFERENT stem produces the rogue-responder case: a
 *                  well-formed response with a correct CertID, signed by somebody the
 *                  issuer never authorised, which is the case that proves the
 *                  verifier checks the SIGNER rather than only reading the status out
 *                  of the staple;
 *   status         TF_OCSP_GOOD or TF_OCSP_REVOKED;
 *   sha256_certid  non-zero builds the CertID with SHA-256, zero with SHA-1. The
 *                  digest is the RESPONDER'S choice, so the suite uses both and a
 *                  verifier that understood only one would fail one required case;
 *   thisupd_offset seconds from now for thisUpdate;
 *   nextupd_offset seconds from now for nextUpdate, or TF_OCSP_NO_NEXT_UPDATE for a
 *                  response with no nextUpdate at all -- which is legal, and which
 *                  the verifier must refuse rather than treat as fresh for ever.
 *
 * Returns 0 on success. The response is a real signed OCSPResponse that OpenSSL's
 * own OCSP_basic_verify() accepts when the signer is the issuer, so the revocation
 * case is a revocation and not a corrupted signature.
 * --------------------------------------------------------------------------- */
#define TF_OCSP_GOOD 0
#define TF_OCSP_REVOKED 1
#define TF_OCSP_NO_NEXT_UPDATE (-2)

int tf_tls_make_ocsp(const char *dir, const char *stem, const char *issuer_stem,
                     const char *subject_stem, const char *signer_stem,
                     int status, int sha256_certid, long thisupd_offset,
                     long nextupd_offset);

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
