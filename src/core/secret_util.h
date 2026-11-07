/* secret_util.h -- the one shared secret-file open and constant-time compare.
 *
 * Both secret stores (sasl_framework.c's credential store and account_store.c's
 * registry) read files of passwords under the same discipline, and compare
 * salted digests under the same comparison. One copy rather than two, so the
 * refusal reasons and the comparison cannot drift apart between the two
 * loaders.
 *
 * WHY A FILE OF ITS OWN rather than living in sasl_framework.c: that file is
 * on test_close_sites.c's never-close list, and this open owns a descriptor
 * it must close on every failure path. An exception there would weaken the
 * audit for a file that otherwise never touches close(); a neutral home costs
 * one module and keeps the audit exact. */
#ifndef IRC_SECRET_UTIL_H
#define IRC_SECRET_UTIL_H

#include <stddef.h>
#include <stdio.h>

typedef enum {
    SECRET_OPEN_OK = 0,
    SECRET_OPEN_FAIL_OPEN,
    SECRET_OPEN_FAIL_FSTAT,
    SECRET_OPEN_NOT_REGULAR,
    SECRET_OPEN_BAD_MODE
} secret_open_status_t;

/* Open `path` as a secret file: open() first with O_NOFOLLOW|O_CLOEXEC, then
 * fstat() the descriptor, requiring S_ISREG and clear group/world bits.
 * Returns the stream on success, NULL on any failure, reporting the reason in
 * `status` (and the offending mode in `mode_out` for BAD_MODE) so the CALLER
 * can print its own [observable] line -- which is what keeps each loader's
 * prefix byte-identical. NULL/empty path is silent NULL, as before. */
FILE *secret_file_open(const char *path, secret_open_status_t *status,
                       unsigned *mode_out);

/* 1 when the two fixed-length buffers hold the same bytes, in time that
 * depends only on their LENGTH and not on their contents. Both sides here are
 * digests; the comparison is hash-against-hash. */
int secret_const_time_eq(const unsigned char *a, const unsigned char *b,
                         size_t n);

#endif /* IRC_SECRET_UTIL_H */
