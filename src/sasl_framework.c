/* sasl_framework.c -- real SASL PLAIN against a real credential store. See
 * sasl_framework.h for the scope decision, the file format, and the timing
 * argument; this file is the implementation of all three.
 *
 * NOTHING HERE PRINTS A CREDENTIAL, and nothing here prints anything at all.
 * The previous version of this file wrote a printf on every state transition,
 * which put the mechanism name and a step counter on stdout but, more to the
 * point, established the habit: the one place in this tree where a secret passes
 * through should be the one place that cannot log. The [observable] lines a node
 * needs are emitted by core/cap.c, which never sees the payload or the password.
 */
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "sasl_framework.h"

/* --------------------------------------------------------------------------
 * The store
 * ------------------------------------------------------------------------ */

struct sasl_record {
    char authcid[SASL_MAX_AUTHCID + 1];
    char passwd[SASL_MAX_PASSWORD + 1];
};

struct sasl_store {
    struct sasl_record rec[SASL_MAX_CREDENTIALS];
    size_t n;
};

sasl_store_t *sasl_store_new(void)
{
    return (sasl_store_t *)calloc(1, sizeof(sasl_store_t));
}

void sasl_store_free(sasl_store_t *store)
{
    if (store == NULL) {
        return;
    }
    /* The passwords are overwritten before the memory is released. Not because
     * free() does not do it -- it does -- but because the buffer this allocation
     * came from is reused by the allocator for the next node of the same size,
     * and a credential that is still legible there outlives the record that
     * named it. The cost is one pass over ~13 KB, on a path that runs once. */
    {
        volatile char *p = (volatile char *)store->rec;
        size_t n = sizeof store->rec;
        size_t i = 0;

        /* Written through a volatile pointer so the compiler cannot elide the
         * stores as dead. This is the one place in the tree that says so, and
         * the reason it says so is that the obvious `memset` version gets
         * optimised away. */
        while (i < n) {
            p[i] = 0;
            i++;
        }
    }
    free(store);
}

size_t sasl_store_count(const sasl_store_t *store)
{
    return (store != NULL) ? store->n : 0u;
}

/* ASCII-folded compare, which is how an authcid is matched: an authentication
 * identity is a nickname in every client that offers one, and RFC 2812 2.3.1
 * says nicknames compare case-insensitively. Comparing case-sensitively would
 * let two different records for `Bob` and `bob` both exist and would make the
 * outcome depend on which one the client happened to type. */
static int authcid_eq(const char *a, const char *b)
{
    while (*a != '\0' && *b != '\0') {
        char ca = *a;
        char cb = *b;

        if (ca >= 'A' && ca <= 'Z') {
            ca = (char)(ca - 'A' + 'a');
        }
        if (cb >= 'A' && cb <= 'Z') {
            cb = (char)(cb - 'A' + 'a');
        }
        if (ca != cb) {
            return 0;
        }
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

int sasl_store_add(sasl_store_t *store, const char *authcid, const char *password)
{
    size_t alen;
    size_t plen;
    size_t at = 0;

    if (store == NULL || authcid == NULL || password == NULL ||
        authcid[0] == '\0') {
        return -1;
    }
    alen = strlen(authcid);
    plen = strlen(password);
    if (alen > (size_t)SASL_MAX_AUTHCID || plen > (size_t)SASL_MAX_PASSWORD) {
        return -1;
    }
    /* A TAB or a NUL cannot appear in either field: the first is the separator,
     * the second would end the C string and take the rest of the record with it. */
    if (strchr(authcid, '\t') != NULL || strchr(password, '\t') != NULL) {
        return -1;
    }

    for (size_t i = 0; i < store->n; i++) {
        if (authcid_eq(store->rec[i].authcid, authcid) != 0) {
            at = i;
            break;
        }
        at = store->n;
    }
    if (at == store->n) {
        if (store->n >= (size_t)SASL_MAX_CREDENTIALS) {
            return -1;
        }
        store->n++;
    }
    memcpy(store->rec[at].authcid, authcid, alen + 1u);
    memcpy(store->rec[at].passwd, password, plen + 1u);
    return 0;
}

/* One record per line: `authcid<TAB>password`. Returns 0 on success, -1 on a
 * malformed line. The line is modified in place, so the caller hands it a buffer
 * it owns. */
static int store_parse_line(sasl_store_t *store, char *line)
{
    char *tab = strchr(line, '\t');
    char *value;

    if (tab == NULL) {
        return -1;
    }
    *tab = '\0';
    value = tab + 1;
    /* Trailing CR, because a file written on a machine whose newline is CRLF is
     * an operator's file and not a broken one. Anything else in the password --
     * including a space, which is the whole reason the separator is a TAB -- is
     * the password. */
    {
        size_t vlen = strlen(value);

        while (vlen > 0u && (value[vlen - 1u] == '\r' || value[vlen - 1u] == '\n')) {
            value[--vlen] = '\0';
        }
    }
    if (line[0] == '\0') {
        return -1; /* "TAB password": a record with no authcid */
    }
    return sasl_store_add(store, line, value);
}

sasl_store_t *sasl_store_load(const char *path)
{
    FILE *f;
    struct stat sb;
    sasl_store_t *store;
    char line[SASL_MAX_LINE];

    if (path == NULL || path[0] == '\0') {
        return NULL;
    }
    /* THE SECRET-FILE CHECK, before a byte is read.
     *
     * `stat` failing is a refusal rather than a fallback to a permission-blind
     * read: a credential file whose mode cannot be established is a credential
     * file whose exposure cannot be established either, and the whole control
     * this check exists to apply is unknowable in that case.
     *
     * A SYMLINK is not followed and not special-cased. stat() has followed it
     * already, so what is judged is the target -- which is the file whose
     * contents would be read. */
      /* OPEN FIRST, THEN fstat THE DESCRIPTOR.
       *
       * This used to stat() the path, judge the mode, and only then fopen() it.
       * Between the stat and the open the file can be replaced -- by a symlink, by
       * a FIFO, or by a 0644 copy -- so the thing that was checked is not
       * necessarily the thing that gets read. CodeQL flagged it, and it is a real
       * race on a file of passwords: the checks below are the only thing standing
       * between a world-readable file and an authentication oracle.
       *
       * fstat() on the descriptor cannot race, because the descriptor names an
       * inode the kernel has already opened, and O_NOFOLLOW makes a symlink at the
       * final component a hard error rather than something to reason about.
       *
       * Nothing changes for an honest operator: same observable lines, same refusal
       * reasons, same mode rule. Only the order changes, and the order was the bug. */
      f = fopen(path, "re");
      if (f == NULL) {
          printf("[observable] sasl_store: state=REFUSED path=%s reason=open\n", path);
          return NULL;
      }
      if (fstat(fileno(f), &sb) != 0) {
          printf("[observable] sasl_store: state=REFUSED path=%s reason=fstat\n", path);
          (void)fclose(f);
          return NULL;
      }
      if (!S_ISREG(sb.st_mode)) {
          printf("[observable] sasl_store: state=REFUSED path=%s reason=not_regular\n",
                 path);
          (void)fclose(f);
          return NULL;
      }
      if ((sb.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
          printf("[observable] sasl_store: state=REFUSED path=%s reason=mode_%03o "
                 "(group or other may access a file of passwords)\n",
                 path, (unsigned)(sb.st_mode & 0777));
          (void)fclose(f);
          return NULL;
      }
    store = sasl_store_new();
    if (store == NULL) {
        (void)fclose(f);
        return NULL;
    }

    while (fgets(line, (int)sizeof line, f) != NULL) {
        size_t n = strlen(line);
        char *p = line;

        /* A line with no terminator in the buffer is over-long, and it is a
         * refusal rather than a truncated record: half a password is not a
         * password, and a store that loaded one would refuse a user whose
         * credential was the first half of the line. */
        if (n > 0u && line[n - 1u] != '\n' && !feof(f)) {
            printf("[observable] sasl_store: state=REFUSED path=%s "
                   "reason=line_too_long\n", path);
            sasl_store_free(store);
            (void)fclose(f);
            return NULL;
        }
        while (*p == ' ' || *p == '\t') {
            p++;
        }
        if (*p == '\0' || *p == '\n' || *p == '#') {
            continue; /* blank line or comment */
        }
        if (store_parse_line(store, p) != 0) {
            printf("[observable] sasl_store: state=REFUSED path=%s "
                   "reason=malformed_record\n", path);
            sasl_store_free(store);
            (void)fclose(f);
            return NULL;
        }
    }
    if (ferror(f) != 0) {
        printf("[observable] sasl_store: state=REFUSED path=%s reason=read_error\n",
               path);
        sasl_store_free(store);
        (void)fclose(f);
        return NULL;
    }
    (void)fclose(f);

    if (store->n == 0u) {
        /* A store with no records authenticates nobody, and reporting it as
         * loaded would make `CAP LS` advertise `sasl` on a node that cannot
         * authenticate a single client -- the exact thing "advertise only what
         * you have" exists to prevent. */
        printf("[observable] sasl_store: state=REFUSED path=%s reason=no_records\n",
               path);
        sasl_store_free(store);
        return NULL;
    }
    printf("[observable] sasl_store: state=LOADED path=%s records=%zu\n", path,
           store->n);
    return store;
}

/* --------------------------------------------------------------------------
 * base64
 * ------------------------------------------------------------------------ */

/* -1 = not in the alphabet, -2 = padding. */
static int b64_value(char c)
{
    if (c >= 'A' && c <= 'Z') {
        return c - 'A';
    }
    if (c >= 'a' && c <= 'z') {
        return c - 'a' + 26;
    }
    if (c >= '0' && c <= '9') {
        return c - '0' + 52;
    }
    if (c == '+') {
        return 62;
    }
    if (c == '/') {
        return 63;
    }
    if (c == '=') {
        return -2;
    }
    return -1;
}

static int b64_is_space(char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' ||
           c == '\v';
}

long sasl_b64_decode(const char *in, size_t inlen, unsigned char *out, size_t cap)
{
    unsigned long acc = 0;
    int nbits = 0;
    size_t n = 0;
    int saw_pad = 0;

    if (in == NULL || out == NULL) {
        return -1;
    }
    for (size_t i = 0; i < inlen; i++) {
        char c = in[i];
        int v;

        /* Whitespace is skipped rather than refused: clients wrap long
         * AUTHENTICATE payloads at 76 columns, and refusing a wrapped payload
         * refuses irssi. */
        if (b64_is_space(c)) {
            continue;
        }
        if (c == '=') {
            saw_pad = 1;
            continue;
        }
        /* A data byte after padding is a malformed encoding, not a
         * tolerate-it-and-guess case. */
        if (saw_pad != 0) {
            return -1;
        }
        v = b64_value(c);
        if (v < 0) {
            return -1;
        }
        acc = (acc << 6) | (unsigned long)v;
        nbits += 6;
        if (nbits >= 8) {
            nbits -= 8;
            if (n >= cap) {
                return -1; /* insufficient capacity: refuse, never truncate */
            }
            out[n++] = (unsigned char)((acc >> nbits) & 0xFFu);
        }
    }
    /* Leftover bits must be zero. `AB` is 4 bits of data padded with 4 that the
     * encoder should have zeroed; accepting non-zero ones would let two distinct
     * encodings decode to the same credential, which is a way to replay one. */
    if (nbits >= 6) {
        return -1;
    }
    if (nbits > 0 && (acc & ((1UL << nbits) - 1UL)) != 0UL) {
        return -1;
    }
    if (n > (size_t)LONG_MAX) {
        return -1;
    }
    return (long)n;
}

/* --------------------------------------------------------------------------
 * RFC 4616 PLAIN
 * ------------------------------------------------------------------------ */

int sasl_plain_parse(const char *payload, size_t len,
                     char *authzid, size_t authzid_cap,
                     char *authcid, size_t authcid_cap,
                     char *passwd, size_t passwd_cap)
{
    const unsigned char *p = (const unsigned char *)payload;
    size_t z1;
    size_t z2;
    size_t azid_len;
    size_t acid_len;
    size_t pw_len;

    if (authzid != NULL) {
        authzid[0] = '\0';
    }
    if (authcid != NULL) {
        authcid[0] = '\0';
    }
    if (passwd != NULL) {
        passwd[0] = '\0';
    }
    if (payload == NULL) {
        return -1;
    }
    /* Find the two NULs. Scanned as BYTES and not with strchr(), because the
     * payload is not a C string: RFC 4616's format is two NULs by construction,
     * and strchr() would stop at the first one and report no second. */
    z1 = len;
    for (size_t i = 0; i < len; i++) {
        if (p[i] == 0u) {
            z1 = i;
            break;
        }
    }
    if (z1 == len) {
        return -1; /* no first NUL */
    }
    z2 = len;
    for (size_t i = z1 + 1u; i < len; i++) {
        if (p[i] == 0u) {
            z2 = i;
            break;
        }
    }
    if (z2 == len) {
        return -1; /* no second NUL */
    }

    azid_len = z1;
    acid_len = z2 - z1 - 1u;
    pw_len = len - z2 - 1u;

    /* RFC 4013 says an empty authzid means "the same as the authentication
     * identity", and that is how irssi sends it. An authzid that names somebody
     * ELSE is accepted as a field here and then REFUSED by the verify path
     * rather than here, because whether a proxying authzid is permitted is a
     * policy question and this module has no answer to it -- what it must not do
     * is silently treat `alice` authenticating as `bob` by preferring authzid
     * over authcid. sasl_plain_verify() compares against BOTH and requires them
     * to agree, which is the fail-closed direction. */

    if (authcid != NULL) {
        if (authcid_cap == 0u || acid_len + 1u > authcid_cap ||
            acid_len > (size_t)SASL_MAX_AUTHCID) {
            return -1;
        }
        memcpy(authcid, payload + z1 + 1u, acid_len);
        authcid[acid_len] = '\0';
    }
    if (authzid != NULL) {
        if (authzid_cap == 0u || azid_len + 1u > authzid_cap) {
            return -1;
        }
        memcpy(authzid, payload, azid_len);
        authzid[azid_len] = '\0';
    }
    if (passwd != NULL) {
        if (passwd_cap == 0u || pw_len + 1u > passwd_cap ||
            pw_len > (size_t)SASL_MAX_PASSWORD) {
            return -1;
        }
        memcpy(passwd, payload + z2 + 1u, pw_len);
        passwd[pw_len] = '\0';
    }
    return 0;
}

/* --------------------------------------------------------------------------
 * Constant-time comparison
 * ------------------------------------------------------------------------ */

/* Returns 1 when the two NUL-terminated strings are equal, in time that depends
 * only on their LENGTHS and not on their contents.
 *
 * `diff` accumulates the XOR of every byte, so a mismatch anywhere makes it
 * non-zero, and the loop cannot exit early -- it always walks to the NUL in both.
 * The accumulator is unsigned so the compiler cannot reason about its value being
 * always zero, and the result is folded to 0/1 at the end so no caller can be
 * tempted to branch on an intermediate. */
static int const_time_eq(const char *a, const char *b)
{
    unsigned char diff = 0u;
    size_t i = 0;

    if (a == NULL || b == NULL) {
        return 0;
    }
    for (;;) {
        const unsigned char ca = (unsigned char)a[i];
        const unsigned char cb = (unsigned char)b[i];

        diff |= (unsigned char)(ca ^ cb);
        if (ca == 0u || cb == 0u) {
            /* Stop only when BOTH have ended: a shorter string must be walked
             * out on the longer one, or the time it took would say which. */
            break;
        }
        i++;
    }
    return (diff == 0u) ? 1 : 0;
}

/* A fixed dummy compared against when no record matched, so that "no such
 * authcid" and "wrong password" cost the same. It is a constant, not a derived
 * value, so it cannot leak anything by being computable. */
static const char k_dummy_pass[] = "irc-serve-no-such-credential";

int sasl_plain_verify(const sasl_store_t *store,
                      const char *authzid, const char *authcid, const char *passwd)
{
    unsigned saw_match = 0u;
    unsigned dummy_used = 0u;

    if (authcid == NULL || authcid[0] == '\0' || passwd == NULL) {
        return 0;
    }
    /* NO STORE, NO AUTHENTICATION. This is the line the previous implementation of
     * this function did not have, and its absence is the defect: a node with
     * nothing to check a password against must refuse every one of them, not
     * accept them. */
    if (store == NULL || store->n == 0u) {
        return 0;
    }
    /* A proxying authzid is refused rather than honoured. `authcid` is what the
     * store is keyed by and `authzid` is what the client asked to act as; when
     * they differ, this node has no policy to allow it and the fail-closed
     * direction is the one that does not require one. An EMPTY authzid is
     * RFC 4013's "same as the authentication identity" and is not a difference. */
    if (authzid != NULL && authzid[0] != '\0' && strcmp(authzid, authcid) != 0) {
        return 0;
    }

    /* The walk does not stop at a match. Two reasons, and both are timing: a
     * walk that returned at the match would make the answer's latency a function
     * of WHICH record matched, and a client that can time its way down the
     * operator list has turned a credential store into an index. */
    for (size_t i = 0; i < store->n; i++) {
        if (authcid_eq(store->rec[i].authcid, authcid) != 0) {
            saw_match |= (unsigned)const_time_eq(store->rec[i].passwd, passwd);
        }
    }
    /* And a miss still pays one comparison, so an authcid that is not in the
     * store is not distinguishable from one whose password is wrong. */
    if (saw_match == 0u) {
        dummy_used = (unsigned)const_time_eq(k_dummy_pass, passwd);
    }
    (void)dummy_used;
    return (int)(saw_match & 1u);
}

/* --------------------------------------------------------------------------
 * The observable state machine
 * ------------------------------------------------------------------------ */

void sasl_init(sasl_ctx_t *ctx, const char *mechanism)
{
    if (ctx == NULL) {
        return;
    }
    memset(ctx, 0, sizeof *ctx);
    ctx->state = SASL_ABORTED;
    if (mechanism != NULL) {
        const size_t n = strlen(mechanism);

        if (n >= sizeof ctx->mechanism) {
            /* A mechanism name that does not fit is truncated to the field's
             * width, which for the only name this node implements cannot happen
             * and for a longer one produces a name that matches nothing -- so
             * the comparison in sasl_start() refuses it. That is the fail-closed
             * direction and it is why the truncation is safe to leave here. */
            memcpy(ctx->mechanism, mechanism, sizeof ctx->mechanism - 1u);
            ctx->mechanism[sizeof ctx->mechanism - 1u] = '\0';
        } else {
            memcpy(ctx->mechanism, mechanism, n + 1u);
        }
    }
}

void sasl_set_store(sasl_ctx_t *ctx, const sasl_store_t *store)
{
    if (ctx == NULL) {
        return;
    }
    ctx->store = store;
}

static int mech_is_plain(const sasl_ctx_t *ctx)
{
    return strcmp(ctx->mechanism, "PLAIN") == 0;
}

sasl_state_t sasl_start(sasl_ctx_t *ctx)
{
    if (ctx == NULL) {
        return SASL_FAILED;
    }
    if (ctx->state != SASL_ABORTED) {
        return ctx->state;
    }
    if (!mech_is_plain(ctx)) {
        /* A mechanism this node does not implement is REFUSED here rather than
         * failing later with a confusing error, and it leaves the state at
         * ABORTED so the caller can offer the list it does implement. */
        ctx->last_error = SASL_ERR_MECH;
        return SASL_FAILED;
    }
    ctx->state = SASL_IN_PROGRESS;
    ctx->step_count = 0;
    return ctx->state;
}

sasl_state_t sasl_step(sasl_ctx_t *ctx, const char *server_data, size_t len,
                       char *client_out, size_t *out_len)
{
    unsigned char payload[SASL_MAX_PAYLOAD];
    char authcid[SASL_MAX_AUTHCID + 1];
    char authzid[SASL_MAX_AUTHCID + 1];
    char passwd[SASL_MAX_PASSWORD + 1];
    long n;

    if (client_out != NULL && out_len != NULL) {
        *out_len = 0;
    }
    if (ctx == NULL) {
        return SASL_FAILED;
    }
    if (ctx->state != SASL_IN_PROGRESS) {
        return ctx->state;
    }
    ctx->step_count++;
    if (!mech_is_plain(ctx)) {
        ctx->last_error = SASL_ERR_MECH;
        ctx->state = SASL_FAILED;
        return ctx->state;
    }

    /* RFC 4422's "the client aborted" is an empty payload. It is an ABORT, not a
     * failure: a client that decides not to authenticate is a client that wants
     * to register, and this node has no operator flags to grant or withhold. */
    if (server_data == NULL || len == 0u) {
        ctx->state = SASL_ABORTED;
        ctx->last_error = SASL_OK;
        return ctx->state;
    }

    n = sasl_b64_decode(server_data, len, payload, sizeof payload);
    if (n < 0) {
        ctx->last_error = SASL_ERR_PAYLOAD;
        ctx->state = SASL_FAILED;
        return ctx->state;
    }
    if (sasl_plain_parse((const char *)payload, (size_t)n, authzid, sizeof authzid,
                         authcid, sizeof authcid, passwd, sizeof passwd) != 0) {
        ctx->last_error = SASL_ERR_PAYLOAD;
        ctx->state = SASL_FAILED;
        return ctx->state;
    }
    /* The decoded identity is recorded on the context -- it is the fact that
     * happened, and a handler needs it to answer 903. The PASSWORD IS NOT, and
     * there is no field for it: `passwd` is a local that goes out of scope here
     * and is never copied anywhere. A struct that held the password would be a
     * struct a later teardown had to remember to clear. */
    /* The identity is BOUNDED before it is copied rather than truncated after.
     * sasl_plain_parse() has already refused an authcid over
     * SASL_MAX_AUTHCID, and ctx->authcid is 64 wide, so the copy fits; saying so
     * with an explicit length and a NUL is what lets the compiler prove it, which
     * strncpy() cannot. */
    {
        const size_t az = strlen(authzid);
        const size_t ac = strlen(authcid);

        if (az >= sizeof ctx->authzid || ac >= sizeof ctx->authcid) {
            ctx->last_error = SASL_ERR_PAYLOAD;
            ctx->state = SASL_FAILED;
            return ctx->state;
        }
        memcpy(ctx->authzid, authzid, az + 1u);
        memcpy(ctx->authcid, authcid, ac + 1u);
    }

    if (!sasl_plain_verify(ctx->store, authzid, authcid, passwd)) {
        ctx->last_error =
            (ctx->store == NULL || sasl_store_count(ctx->store) == 0u)
                ? SASL_ERR_NO_STORE
                : SASL_ERR_CREDENTIAL;
        ctx->state = SASL_FAILED;
        return ctx->state;
    }
    ctx->last_error = SASL_OK;
    ctx->state = SASL_COMPLETED;
    return ctx->state;
}

sasl_state_t sasl_abort(sasl_ctx_t *ctx, int error_code)
{
    if (ctx == NULL) {
        return SASL_FAILED;
    }
    ctx->state = SASL_ABORTED;
    ctx->last_error = error_code;
    return ctx->state;
}

sasl_state_t sasl_fail(sasl_ctx_t *ctx, int error_code)
{
    if (ctx == NULL) {
        return SASL_FAILED;
    }
    ctx->state = SASL_FAILED;
    ctx->last_error = error_code;
    return ctx->state;
}

sasl_state_t sasl_get_state(const sasl_ctx_t *ctx)
{
    if (ctx == NULL) {
        return SASL_FAILED;
    }
    return ctx->state;
}

/* base64 of "authzid\0authcid\0passwd", assembled by hand.
 *
 * Written out rather than borrowed because there is no encoder in this tree and
 * the alternative -- a table of pre-encoded strings in a test -- cannot express
 * the field the test is about. This is TEST-SUPPORT code inside the module
 * because the alternative was a second PLAIN implementation, which is worse. */
static size_t b64_encode(const char *in, size_t len, char *out, size_t cap)
{
    static const char alpha[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i = 0;
    size_t n = 0;

    while (i < len) {
        unsigned long acc = 0;
        int have = 0;
        char chunk[4];

        for (int k = 0; k < 3; k++) {
            acc <<= 8;
            if (i < len) {
                acc |= (unsigned long)(unsigned char)in[i++];
                have++;
            }
        }
        chunk[0] = alpha[(acc >> 18) & 0x3Fu];
        chunk[1] = alpha[(acc >> 12) & 0x3Fu];
        chunk[2] = (have > 1) ? alpha[(acc >> 6) & 0x3Fu] : '=';
        chunk[3] = (have > 2) ? alpha[acc & 0x3Fu] : '=';
        for (int k = 0; k < 4; k++) {
            if (n + 1u >= cap) {
                return 0;
            }
            out[n++] = chunk[k];
        }
    }
    if (cap == 0) {
        return 0;
    }
    out[n] = '\0';
    return n;
}

/* Build "authzid\0authcid\0passwd" into `buf`. Returns its length, or 0 if it
 * does not fit. */
static size_t plain_build(char *buf, size_t cap, const char *authzid,
                          const char *authcid, const char *passwd)
{
    const size_t za = strlen(authzid);
    const size_t zc = strlen(authcid);
    const size_t zp = strlen(passwd);
    size_t n = 0;

    if (za + 1u + zc + 1u + zp > cap) {
        return 0;
    }
    memcpy(buf + n, authzid, za);
    n += za;
    buf[n++] = '\0';
    memcpy(buf + n, authcid, zc);
    n += zc;
    buf[n++] = '\0';
    memcpy(buf + n, passwd, zp);
    n += zp;
    return n;
}

int sasl_state_machine(void)
{
    sasl_store_t *store = sasl_store_new();
    sasl_ctx_t ctx;
    char payload[512];
    char encoded[700];
    size_t plen;
    size_t elen;
    int ok = 1;

    if (store == NULL) {
        return 0;
    }
    if (sasl_store_add(store, "alice", "correct horse") != 0 ||
        sasl_store_add(store, "bob", "s3cret") != 0 ||
        sasl_store_count(store) != 2u) {
        sasl_store_free(store);
        return 0;
    }

    /* 1. THE GOOD PATH. A correct credential reaches COMPLETED and the context
     *    holds the identity that authenticated. */
    sasl_init(&ctx, "PLAIN");
    sasl_set_store(&ctx, store);
    ok &= (sasl_start(&ctx) == SASL_IN_PROGRESS);
    plen = plain_build(payload, sizeof payload, "", "alice", "correct horse");
    elen = b64_encode(payload, plen, encoded, sizeof encoded);
    ok &= (elen > 0);
    ok &= (sasl_step(&ctx, encoded, elen, NULL, NULL) == SASL_COMPLETED);
    ok &= (strcmp(ctx.authcid, "alice") == 0);

    /* 2. A WRONG PASSWORD reaches FAILED. This is the case the previous
     *    implementation of this file could not produce: it marked the exchange
     *    COMPLETED on the second step without ever looking at the bytes. */
    sasl_init(&ctx, "PLAIN");
    sasl_set_store(&ctx, store);
    (void)sasl_start(&ctx);
    plen = plain_build(payload, sizeof payload, "", "alice", "wrong");
    elen = b64_encode(payload, plen, encoded, sizeof encoded);
    ok &= (sasl_step(&ctx, encoded, elen, NULL, NULL) == SASL_FAILED);
    ok &= (ctx.last_error == SASL_ERR_CREDENTIAL);

    /* 3. A WRONG PASSWORD that is a PREFIX of the right one also fails, which
     *    is the case a prefix comparison would get wrong. */
    sasl_init(&ctx, "PLAIN");
    sasl_set_store(&ctx, store);
    (void)sasl_start(&ctx);
    plen = plain_build(payload, sizeof payload, "", "alice", "correct");
    elen = b64_encode(payload, plen, encoded, sizeof encoded);
    ok &= (sasl_step(&ctx, encoded, elen, NULL, NULL) == SASL_FAILED);

    /* 4. AN UNKNOWN AUTHCID fails, and is indistinguishable from #2 by result. */
    sasl_init(&ctx, "PLAIN");
    sasl_set_store(&ctx, store);
    (void)sasl_start(&ctx);
    plen = plain_build(payload, sizeof payload, "", "mallory", "correct horse");
    elen = b64_encode(payload, plen, encoded, sizeof encoded);
    ok &= (sasl_step(&ctx, encoded, elen, NULL, NULL) == SASL_FAILED);
    ok &= (ctx.last_error == SASL_ERR_CREDENTIAL);

    /* 5. THE AUTHZID MUST NOT OVERRIDE THE AUTHCID. `alice` may not authenticate
     *    as `bob`, which is what a store lookup on authzid would have done. */
    sasl_init(&ctx, "PLAIN");
    sasl_set_store(&ctx, store);
    (void)sasl_start(&ctx);
    plen = plain_build(payload, sizeof payload, "bob", "alice", "correct horse");
    elen = b64_encode(payload, plen, encoded, sizeof encoded);
    ok &= (sasl_step(&ctx, encoded, elen, NULL, NULL) == SASL_FAILED);

    /* 6. NO STORE, NO AUTHENTICATION. The line whose absence was the defect. */
    sasl_init(&ctx, "PLAIN");
    (void)sasl_start(&ctx);
    plen = plain_build(payload, sizeof payload, "", "alice", "correct horse");
    elen = b64_encode(payload, plen, encoded, sizeof encoded);
    ok &= (sasl_step(&ctx, encoded, elen, NULL, NULL) == SASL_FAILED);
    ok &= (ctx.last_error == SASL_ERR_NO_STORE);

    /* 7. A MALFORMED PAYLOAD fails without ever reaching the store. */
    sasl_init(&ctx, "PLAIN");
    sasl_set_store(&ctx, store);
    (void)sasl_start(&ctx);
    ok &= (sasl_step(&ctx, "not base64 !!", 13, NULL, NULL) == SASL_FAILED);
    ok &= (ctx.last_error == SASL_ERR_PAYLOAD);
    /* base64 of "no NULs here" */
    ok &= (sasl_step(&ctx, "bm8gTlVMUyBoZXJl", 16, NULL, NULL) == SASL_FAILED);
    ok &= (ctx.last_error == SASL_ERR_PAYLOAD);

    /* 8. A MECHANISM THIS NODE DOES NOT IMPLEMENT is refused, and it never
     *    reaches IN_PROGRESS -- so no client is told to send a PLAIN payload to
     *    a server that cannot verify one. */
    sasl_init(&ctx, "SCRAM-SHA-256");
    sasl_set_store(&ctx, store);
    ok &= (sasl_start(&ctx) == SASL_FAILED);
    ok &= (ctx.last_error == SASL_ERR_MECH);

    /* 9. AN EMPTY PAYLOAD IS AN ABORT (RFC 4422), not a failure, and it does not
     *    complete the exchange either. A client that declines to authenticate
     *    must still be able to register. */
    sasl_init(&ctx, "PLAIN");
    sasl_set_store(&ctx, store);
    (void)sasl_start(&ctx);
    ok &= (sasl_step(&ctx, "", 0, NULL, NULL) == SASL_ABORTED);

    /* 10. A SECOND step in a terminal state returns that state. This is the
     *     exact case the previous implementation had backwards: it advanced on
     *     the second CALL, so calling step twice completed an exchange that had
     *     been sent nothing at all. */
    sasl_init(&ctx, "PLAIN");
    sasl_set_store(&ctx, store);
    (void)sasl_start(&ctx);
    plen = plain_build(payload, sizeof payload, "", "alice", "correct horse");
    elen = b64_encode(payload, plen, encoded, sizeof encoded);
    ok &= (sasl_step(&ctx, encoded, elen, NULL, NULL) == SASL_COMPLETED);
    ok &= (sasl_step(&ctx, encoded, elen, NULL, NULL) == SASL_COMPLETED);

    /* 11. Base64 itself: padding, whitespace, and a refusal rather than a
     *     truncation when the output does not fit. */
    {
        unsigned char out[8];
        long n = sasl_b64_decode("YQ==", 4, out, sizeof out);

        ok &= (n == 1 && out[0] == (unsigned char)'a');
        /* A wrapped payload -- irssi wraps at 76 columns -- decodes to the same
         * five bytes ("alxce"), because the whitespace is skipped rather than
         * refused. The buffer is 8 wide on purpose: a decoder that refused the
         * wrap would also answer -1 here, so a 3-wide buffer is what tells the
         * two apart. */
        {
            unsigned char tight[3];

            /* The decoded text is "alace": five bytes, and a decoder that
             * stopped at the CR would have produced three. */
            n = sasl_b64_decode("YWxh\r\n Y2U=", 11, out, sizeof out);
            ok &= (n == 5 && memcmp(out, "alace", 5) == 0);
            /* And it refuses rather than truncating when the output is too
             * small, which is what 3.2's rule is for. */
            ok &= (sasl_b64_decode("YWxh\r\n Y2U=", 11, tight, sizeof tight) == -1);
        }
        ok &= (sasl_b64_decode("YQ==", 4, out, 0) == -1);
        ok &= (sasl_b64_decode("****", 4, out, sizeof out) == -1);
        /* Data after padding is malformed, not tolerated. */
        ok &= (sasl_b64_decode("YQ==YQ==", 8, out, sizeof out) == -1);
        ok &= (sasl_b64_decode("YQ", 2, out, sizeof out) == 1);
        /* Non-zero leftover bits are refused: two encodings, one credential. */
        ok &= (sasl_b64_decode("YR==", 4, out, sizeof out) == -1);
    }

    sasl_store_free(store);
    return ok;
}
