/* account_store.c -- the account registry. See account_store.h for the format,
 * the secret-file discipline, and the argument for why this is a separate file
 * from the credential store.
 *
 * NOTHING HERE PRINTS A PASSWORD, and nothing here prints a whole record
 * either -- the [observable] lines name the PATH and the COUNT, and a store with
 * one credential in it has the same log output as one with sixty-four. The
 * discipline is the one sasl_framework.c established: the module a secret passes
 * through is the module that cannot log.
 */
#include "account_store.h"


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

struct account_record {
    char name[ACCOUNT_MAX_NAME + 1];
    char passwd[ACCOUNT_MAX_PASSWORD + 1];
    long created;
};

struct account_store {
    struct account_record rec[ACCOUNT_MAX_RECORDS];
    size_t n;
};

/* ASCII-folded compare, for the same reason sasl_framework.c's authcid_eq()
 * exists: an account name is a nickname in every client that displays one, and
 * RFC 2812 2.3.1 says nicknames compare case-insensitively. Comparing
 * case-sensitively would let `Alice` and `alice` both exist, and which one a
 * client authenticated as would then decide what other users are shown. */
static int name_eq(const char *a, const char *b)
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

/* Parse a decimal integer that must consume the WHOLE string. strtol() alone
 * accepts "1700000000junk" and stops, and a `created` column that silently
 * became the leading digits would be a wrong fact in a file whose whole purpose
 * is to be a readable record. Returns 0 on success, -1 otherwise. */
static int parse_created(const char *text, long *out)
{
    char *end = NULL;
    long value;

    if (text == NULL || text[0] == '\0') {
        return -1;
    }
    for (const char *p = text; *p != '\0'; p++) {
        if (*p < '0' || *p > '9') {
            return -1;
        }
    }
    value = strtol(text, &end, 10);
    if (end == NULL || *end != '\0') {
        return -1;
    }
    *out = value;
    return 0;
}

account_store_t *account_store_new(void)
{
    return (account_store_t *)calloc(1, sizeof(account_store_t));
}
void account_store_free(account_store_t *store)
{
    if (store == NULL) {
        return;
    }
    /* THE PASSWORDS ARE OVERWRITTEN BEFORE THE MEMORY IS RELEASED, and this is
     * not ceremony. free() does scrub nothing -- it hands the buffer back -- but
     * the allocator reuses that buffer for the next node of the same size, so a
     * password still legible there outlives the record that named it by an
     * arbitrary length of time.
     *
     * THE `volatile` IS THE POINT and it is not decorative: the compiler is
     * entitled to see a block of stores to memory it is about to release, prove
     * the values are dead, and delete the writes. sasl_store_free() carries the
     * identical pass for the identical reason, and this is the second copy
     * rather than a shared helper on purpose -- see the note in the block
     * comment below.
     *
     * WHY A COPY AND NOT A HELPER, since the argument has been made elsewhere in
     * this tree (the federation modules' ASCII fold) and the answer here is different:
     * the two stores are separate FILES, and a shared scrub helper would put a
     * function in one of them that the other had to link -- which is the same
     * coupling that account_store.h argues against for the records themselves.
     * Six lines, written twice, is cheaper than a module boundary crossed to
     * save six lines. */
    {
        volatile char *p = (volatile char *)store->rec;
        const size_t n = sizeof store->rec;
        size_t i = 0;

        while (i < n) {
            p[i] = 0;
            i++;
        }
    }
    free(store);
}

size_t account_store_count(const account_store_t *store)
{
    return (store != NULL) ? store->n : 0u;
}

int account_name_wire_safe(const char *name)
{
    size_t i;

    if (name == NULL || name[0] == '\0') {
        return 0;
    }
    /* AND THE LENGTH, WHICH IS PART OF THE SAME RULE AND WAS MISSING FROM IT.
     *
     * Every field this name reaches is ACCOUNT_MAX_NAME wide -- conn_t::account,
     * chan_remote_t::account, burst_member_t::account -- and a name longer than
     * that is one this node cannot HOLD, which is a stronger statement than one
     * it cannot render. Rendering was the whole of the predicate when there were
     * two callers, both of them on the LOCAL side: account_set() and
     * account_store_add(), and both already bounded the length separately. The
     * two PEER-side callers came with Phase 10.3 and neither had anywhere to
     * bound it, because the rule they were handed says nothing about length:
     *
     *   chan_remote_add()  copy_bounded() TRUNCATES and returns 0, which both call
     *                      sites discard -- so the roster ended up holding a
     *                      DIFFERENT NAME from the one the peer reported, under a
     *                      name that peer will never be asked about again.
     *   burst.c's apply_member()  burst_copy() REFUSES rather than truncating, and
     *                      writes NOTHING -- into a slot of a realloc'd array that
     *                      nothing zeroes. So what the resync went on to install
     *                      was whatever the allocator had left there.
     *
     * Both are the same defect seen from two receivers, and both are closed by
     * one bound in one place, which is what this predicate is FOR: the account
     * header's argument is that a name it refuses is a name no connection can be
     * logged in as, and a name that does not FIT is a name no field can hold,
     * whichever of the two the caller happened to notice.
     *
     * The bound is ACCOUNT_MAX_NAME and not a literal, for the reason the constant
     * is documented with: it is "conn_t::account's bound minus one", so the three
     * fields and the predicate cannot come to disagree about where the edge is. */
    if (strlen(name) > (size_t)ACCOUNT_MAX_NAME) {
        return 0;
    }
    if (name[0] == ':') {
        /* A LEADING colon is the marker 3.2 writes itself; a value that starts
         * with one cannot be told apart from a marker by a parser, and
         * message_format() refuses such a value in every position but the last.
         * The `*` case is the exception and is the reason it is not simply "a
         * colon is bad". */
        return (name[1] == '\0') ? 1 : 0;
    }
    for (i = 0; name[i] != '\0'; i++) {
        const unsigned char ch = (unsigned char)name[i];

        if (ch <= 0x20u || ch == 0x7fu) {
            /* SP, HTAB, CR, LF, every other control byte, and DEL. 3.2 refuses all
             * of them in a parameter, and a parameter is where three of the four
             * places this name appears have to put it. */
            return 0;
        }
    }
    return 1;
}

int account_store_add(account_store_t *store, const char *name,
                      const char *password, long created)
{
    size_t nlen;
    size_t plen;
    size_t at = 0;

    if (store == NULL || name == NULL || password == NULL || name[0] == '\0') {
        return -1;
    }
    nlen = strlen(name);
    plen = strlen(password);
    if (nlen > (size_t)ACCOUNT_MAX_NAME || plen > (size_t)ACCOUNT_MAX_PASSWORD) {
        return -1;
    }
    /* A TAB cannot appear in either field: the first is the separator and the
     * second is what would follow it. A SPACE in the PASSWORD is allowed and is
     * the reason the separator is a TAB rather than a split on whitespace --
     * sasl_store_add() makes the same call for the same reason.
     *
     * AND THE NAME MUST BE PUBLISHABLE, which is the one asymmetry between the two
     * fields and it is Phase 10.3 that made it visible. A password never leaves
     * this process; an account name is a middle parameter of 330 RPL_WHOISACCOUNT,
     * of the JOIN echo and of two S-verbs, and 3.2 can escape nothing in a
     * parameter. account_name_wire_safe() is the rule and account.h is where it is
     * argued; enforcing it HERE rather than only at the renderer is what makes a
     * registry unable to contain a name this node could never show a user.
     *
     * `*` is accepted, because it is what the protocol reserves for "no account"
     * and refusing it here would make a registry unable to hold the one name the
     * wire uses for the absence. */
    if (strchr(password, '\t') != NULL || account_name_wire_safe(name) == 0) {
        return -1;
    }
    for (size_t i = 0; i < store->n; i++) {
        if (name_eq(store->rec[i].name, name) != 0) {
            at = i;
            break;
        }
        at = store->n;
    }
    if (at == store->n) {
        if (store->n >= (size_t)ACCOUNT_MAX_RECORDS) {
            return -1;
        }
        store->n++;
    }
    memcpy(store->rec[at].name, name, nlen + 1u);
    memcpy(store->rec[at].passwd, password, plen + 1u);
    store->rec[at].created = created;
    return 0;
}

/* Returns 1 when the two NUL-terminated strings are equal, in time that depends
 * only on their LENGTHS and not on their contents.
 *
 * Identical in construction to sasl_framework.c's const_time_eq(), and copied
 * rather than shared for the reason account_store_free()'s scrub pass is: the
 * two stores are separate files that do not link to each other, and a helper
 * would be a module boundary crossed to save six lines. */
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
        /* Stop only when BOTH have ended: a shorter string must be walked out
         * on the longer one, or the time the walk took would say which. */
        if (ca == 0u || cb == 0u) {
            break;
        }
        i++;
    }
    return (diff == 0u) ? 1 : 0;
}

/* A fixed dummy compared against when no record matched, so that "no such
 * account" and "wrong password" cost the same. A CONSTANT rather than a derived
 * value, so it cannot leak anything by being computable. */
static const char k_dummy_pass[] = "irc-serve-no-such-account";

int account_store_verify(const account_store_t *store, const char *name,
                         const char *password)
{
    unsigned saw_match = 0u;
    unsigned dummy_used = 0u;

    if (name == NULL || name[0] == '\0' || password == NULL) {
        return 0;
    }
    /* NO REGISTRY, NO ACCOUNT CLAIM. The fail-closed direction, and the reason a
     * node started without --account-store cannot have a logged-in client even
     * if its credential store would verify one: there is nothing on this node
     * that says the account exists. */
    if (store == NULL || store->n == 0u) {
        return 0;
    }
    for (size_t i = 0; i < store->n; i++) {
        if (name_eq(store->rec[i].name, name) != 0) {
            saw_match |= (unsigned)const_time_eq(store->rec[i].passwd, password);
        }
    }
    /* A miss still pays one comparison, so an account that is not in the registry
     * is not distinguishable by timing from one whose password is wrong. */
    if (saw_match == 0u) {
        dummy_used = (unsigned)const_time_eq(k_dummy_pass, password);
    }
    (void)dummy_used;
    return (int)(saw_match & 1u);
}

/* One record per line: `name TAB password TAB created`. Returns 0 on success, -1
 * on anything else. The line is modified in place, so the caller hands it a
 * buffer it owns -- the same arrangement sasl_framework.c's store_parse_line()
 * uses, and for the same reason: it is on a load path that runs once per process
 * and there is nothing to be gained by allocating. */
static int store_parse_line(account_store_t *store, char *line)
{
    char *tab1;
    char *tab2;
    char *value;
    long created = 0;

    tab1 = strchr(line, '\t');
    if (tab1 == NULL) {
        return -1;
    }
    *tab1 = '\0';
    tab2 = strchr(tab1 + 1, '\t');
    if (tab2 == NULL) {
        return -1;
    }
    *tab2 = '\0';
    value = tab2 + 1;
    /* Trailing CR/LF, because a file written on a machine whose newline is CRLF
     * is an operator's file and not a broken one. Anything else in the
     * timestamp is a refusal -- parse_created() requires digits to the end. */
    {
        size_t vlen = strlen(value);

        while (vlen > 0u &&
               (value[vlen - 1u] == '\r' || value[vlen - 1u] == '\n')) {
            value[--vlen] = '\0';
        }
    }
    if (line[0] == '\0') {
        return -1; /* "TAB password TAB created": a record with no name */
    }
    if (parse_created(value, &created) != 0) {
        return -1;
    }
    /* A FOURTH field is a file written by something that does not mean what
     * this module means. Guessing which three of four are the ones is how a
     * password ends up in a timestamp column, so it is refused. */
    if (strchr(value, '\t') != NULL) {
        return -1;
    }
    return account_store_add(store, line, tab1 + 1, created);
}

account_store_t *account_store_load(const char *path)
{
    FILE *f;
    struct stat sb;
    account_store_t *store;
    char line[ACCOUNT_MAX_LINE];

    if (path == NULL || path[0] == '\0') {
        return NULL;
    }
    /* OPEN FIRST, THEN fstat THE DESCRIPTOR.
     *
     * This is sasl_store_load()'s order and sasl_store_load()'s reason, and the
     * comment is repeated rather than referenced because the sequence is the
     * control: stat()-then-open leaves a window in which the thing that was
     * checked is not the thing that gets read, on a file whose whole content is
     * passwords. fstat() on the descriptor cannot race, and 'e' (O_CLOEXEC)
     * stops the descriptor being inherited across an exec that happens to be
     * running while this node starts.
     *
     * A SYMLINK IS NOT FOLLOWED AND NOT SPECIAL-CASED: fstat() judges the target,
     * which is the file whose bytes would be read. */
    f = fopen(path, "re");
    if (f == NULL) {
        printf("[observable] account_store: state=REFUSED path=%s reason=open\n",
               path);
        return NULL;
    }
    if (fstat(fileno(f), &sb) != 0) {
        printf("[observable] account_store: state=REFUSED path=%s reason=fstat\n",
               path);
        (void)fclose(f);
        return NULL;
    }
    if (!S_ISREG(sb.st_mode)) {
        printf("[observable] account_store: state=REFUSED path=%s "
               "reason=not_regular\n",
               path);
        (void)fclose(f);
        return NULL;
    }
    if ((sb.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
        printf("[observable] account_store: state=REFUSED path=%s reason=mode_%03o "
               "(group or other may access a file of passwords)\n",
               path, (unsigned)(sb.st_mode & 0777));
        (void)fclose(f);
        return NULL;
    }

    store = account_store_new();
    if (store == NULL) {
        (void)fclose(f);
        return NULL;
    }
    while (fgets(line, (int)sizeof line, f) != NULL) {
        const size_t n = strlen(line);
        char *p = line;

        /* A line with no terminator in the buffer is over-long, and it is a
         * REFUSAL rather than a truncated record: half a record is not a record,
         * and a registry that loaded one would answer for a password the
         * operator never wrote. */
        if (n > 0u && line[n - 1u] != '\n' && !feof(f)) {
            printf("[observable] account_store: state=REFUSED path=%s "
                   "reason=line_too_long\n",
                   path);
            account_store_free(store);
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
            printf("[observable] account_store: state=REFUSED path=%s "
                   "reason=malformed_record\n",
                   path);
            account_store_free(store);
            (void)fclose(f);
            return NULL;
        }
    }
    if (ferror(f) != 0) {
        printf("[observable] account_store: state=REFUSED path=%s "
               "reason=read_error\n",
               path);
        account_store_free(store);
        (void)fclose(f);
        return NULL;
    }
    (void)fclose(f);

    if (store->n == 0u) {
        /* A registry with no records holds no accounts, and reporting it as
         * loaded would make this node answer questions about accounts it does
         * not have -- the exact thing "advertise only what you have" exists to
         * prevent, applied to a table rather than to a capability. */
        printf("[observable] account_store: state=REFUSED path=%s "
               "reason=no_records\n",
               path);
        account_store_free(store);
        return NULL;
    }
    printf("[observable] account_store: state=LOADED path=%s records=%zu\n", path,
           store->n);
    return store;
}
