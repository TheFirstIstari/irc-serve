/* secret_util.c -- the shared secret-file open and constant-time compare.
 * See secret_util.h for why this is a file of its own. */
#include "core/secret_util.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

FILE *secret_file_open(const char *path, secret_open_status_t *status,
                       unsigned *mode_out)
{
    struct stat sb;
    int fd;
    FILE *f;

    if (status != NULL) {
        *status = SECRET_OPEN_FAIL_OPEN;
    }
    if (path == NULL || path[0] == '\0') {
        return NULL;
    }
    /* OPEN FIRST, THEN fstat THE DESCRIPTOR.
     *
     * stat()-then-open leaves a window in which the file judged is not the
     * file read, on a file whose whole content is passwords; fstat() on the
     * descriptor cannot race, because the descriptor names an inode the kernel
     * has already opened. O_NOFOLLOW makes a symlink at the final component a
     * hard open error rather than something to reason about, and O_NONBLOCK
     * keeps a FIFO at the path from wedging the loader: the S_ISREG check
     * below refuses it instead. Nothing changes for an honest operator: same
     * refusal reasons, same mode rule. Only the order changed, and the order
     * was the bug. */
    fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) {
        return NULL;
    }
    if (fstat(fd, &sb) != 0) {
        if (status != NULL) {
            *status = SECRET_OPEN_FAIL_FSTAT;
        }
        (void)close(fd);
        return NULL;
    }
    if (!S_ISREG(sb.st_mode)) {
        if (status != NULL) {
            *status = SECRET_OPEN_NOT_REGULAR;
        }
        (void)close(fd);
        return NULL;
    }
    if ((sb.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
        if (status != NULL) {
            *status = SECRET_OPEN_BAD_MODE;
        }
        if (mode_out != NULL) {
            *mode_out = (unsigned)(sb.st_mode & 0777);
        }
        (void)close(fd);
        return NULL;
    }
    /* Regular files ignore O_NONBLOCK on read, so there is nothing to clear. */
    f = fdopen(fd, "r");
    if (f == NULL) {
        (void)close(fd);
        return NULL;
    }
    if (status != NULL) {
        *status = SECRET_OPEN_OK;
    }
    return f;
}

/* `diff` accumulates the XOR of every byte, so a mismatch anywhere makes it
 * non-zero, and the loop cannot exit early -- it always walks the whole
 * length. The accumulator is unsigned so the compiler cannot reason about its
 * value being always zero, and the result is folded to 0/1 at the end so no
 * caller can be tempted to branch on an intermediate. */
int secret_const_time_eq(const unsigned char *a, const unsigned char *b,
                         size_t n)
{
    unsigned diff = 0u;

    if (a == NULL || b == NULL) {
        return 0;
    }
    for (size_t i = 0; i < n; i++) {
        diff |= (unsigned)(a[i] ^ b[i]);
    }
    return (diff == 0u) ? 1 : 0;
}
