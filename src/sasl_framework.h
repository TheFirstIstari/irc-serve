/* sasl_framework.h -- REAL SASL PLAIN, verified against a credential store.
 *
 * Authority: docs/SERVER_DESIGN.md 5 ("implement real SASL PLAIN (base64 ->
 * authzid\0authcid\0passwd -> credential store)"), 7/Phase 8, and RFC 4616.
 *
 * ---------------------------------------------------------------------------
 * WHAT WAS HERE, AND WHY IT IS GONE
 * ---------------------------------------------------------------------------
 * This file used to be a state machine whose `sasl_step()` DISCARDED its input,
 * called `printf("[observable] ...")` four times a call, and marked the exchange
 * COMPLETED on the second step regardless of what -- if anything -- the client
 * sent. A `sasl_framework.c` that answers PLAIN by returning success is the exact
 * defect Phase 6's README described as "a node that is not allowed to be here",
 * and shipping that as authentication would be worse than shipping nothing: a
 * client would be told it authenticated and would act on it.
 *
 * So the state machine is GONE as a concept rather than fixed. What remains is
 * the part that has to be real:
 *
 *   - a CREDENTIAL STORE, loaded from a file the operator supplies, so there is
 *     something for a password to be WRONG against;
 *   - base64 decode of what the client sent;
 *   - RFC 4616's three-NUL-separated field split;
 *   - a COMPARISON that does not leak the password's prefix by timing;
 *   - and a refusal that fails CLOSED when the store is missing, unreadable, or
 *     too permissive.
 *
 * The observable state names (`sasl_state_t`) survive because
 * tests/compliance/test_sasl_handshake.c calls sasl_state_machine(), and a
 * module with no callers is not a place to change a test's API. The entry points
 * now do the real thing; sasl_state_machine() drives them over a store it builds
 * in memory.
 *
 * ---------------------------------------------------------------------------
 * WHAT SASL AUTHENTICATES AGAINST, STATED PLAINLY
 * ---------------------------------------------------------------------------
 * There is no operator credential store in this tree, and there is no
 * NickServ. So this states its own scope rather than implying a larger one:
 *
 *   SASL PLAIN authenticates a CLIENT against THIS NODE'S credential store --
 *   the file named by `--sasl-store` -- and the ONLY thing it establishes is
 *   "this connection proved it holds the password recorded for <authcid>". It
 *   grants NOTHING: no operator flag, no channel privilege, no service, no
 *   exemption from a mode change. `conn_t` has no field a successful SASL would
 *   write, because there is nothing here it could legitimately grant.
 *
 *   Credentials are PER NODE, which is a real limitation and not a design
 *   choice: a federated deployment shares authentication by link auth (2.3),
 *   and this store is not that mechanism. Two nodes in a mesh with two different
 *   `--sasl-store` files will disagree about who a user is, and neither can
 *   detect it. That is stated rather than solved, because solving it means a
 *   credential-propagation protocol and 9's risk table is the right place for
 *   that argument.
 *
 * The alternative designs were considered and rejected rather than overlooked:
 *
 *   NO CHECK AT ALL, or "any password is accepted". This is the failure mode
 *   above and it is worse than having no SASL, because a client believes it
 *   authenticated.
 *   AGAINST THE HOST'S getpwnam(). Real, but it makes a federated node's user
 *   namespace the host's, so a container image's `root` becomes an IRC identity
 *   nobody chose, and the node's `--name` gives no hint of it.
 *   A HASH. Right in the abstract and wrong here: this tree contains no
 *   cryptographic code and hand-rolling a primitive into an authentication path
 *   is a worse outcome than being explicit about what the file is. The file is a
 *   secret store, so it is required to be a SECRET FILE -- see
 *   sasl_store_load() -- and that requirement, not a hash, is the control.
 */
#ifndef IRC_SASL_FRAMEWORK_H
#define IRC_SASL_FRAMEWORK_H

#include <stddef.h>

/* Bounds on the credential store. All of them are constants rather than
 * configuration, and the reason is the one that applies to every one: this is
 * loaded from a path an operator names, and a store whose size depends on a
 * number read from the same file is a store whose bound is the file. */
#define SASL_MAX_AUTHCID    63   /* conn_t::nick's bound minus one; an authcid
                                  * IS a nickname in every client that offers it */
#define SASL_MAX_PASSWORD  128   /* RFC 4013's PLAIN has no length limit, so this
                                  * is ours and is stated, not inherited */
#define SASL_MAX_CREDENTIALS 64  /* a node's operator list is a small set; 64
                                  * records at ~200 bytes is ~13 KB and one
                                  * linear scan per AUTHENTICATE, which is not a
                                  * search algorithm anyone should build here */
#define SASL_MAX_LINE      512   /* one record in the file, NUL included */
#define SASL_MAX_PAYLOAD   1024  /* the DECODED PLAIN payload */
#define SASL_MAX_RESPONSE  1024  /* the base64 text a client may send */

/* Observable SASL state. The names are the ones this module has always had;
 * `FAILED` is terminal and `ABORTED` means "not started or abandoned". */
typedef enum {
    SASL_ABORTED = 0,
    SASL_IN_PROGRESS = 1,
    SASL_COMPLETED = 2,
    SASL_FAILED = 3
} sasl_state_t;

/* An opaque credential store. Declared here and defined in sasl_framework.c, so
 * a caller cannot build one by laying out fields -- the store has to come from
 * sasl_store_load() or sasl_store_new(), which is what keeps the bounds above
 * real. */
typedef struct sasl_store sasl_store_t;

typedef struct {
    sasl_state_t state;
    char         mechanism[32];
    char         authzid[64];
    char         authcid[64];
    int          step_count;
    int          last_error;

    /* The store this context verifies against. NULL MEANS NO STORE, and the
     * verify path treats NULL as "every credential fails" -- fail closed. It is
     * a pointer rather than an owned copy so a node loads the file once and
     * every connection borrows it, which is also why it must outlive every
     * context pointing at it; server_shutdown() frees the store and the loop
     * has stopped by then. */
    const sasl_store_t *store;
} sasl_ctx_t;

/* ---------------------------------------------------------------------------
 * The credential store
 * --------------------------------------------------------------------------- */

/* Load `path`. Returns NULL on ANY failure -- unreadable, not a regular file,
 * group- or world-accessible, malformed, or with no usable record -- and prints
 * one [observable] line naming the reason. There is no partial success: a store
 * that loaded half its file would authenticate half the passwords an operator
 * believes are configured, and the half that fails is discovered by a user
 * being refused.
 *
 * THE FILE IS A SECRET STORE and is checked as one. stat() must succeed and the
 * group and world permission bits must be CLEAR, because a credential file any
 * other account on the host can read is not a credential store -- it is a list
 * of passwords. This is a refusal, not a warning: the cost of getting it wrong
 * is every password on the node, and the cost of getting it right is an operator
 * who has to run `chmod 600`.
 *
 * FORMAT. One record per line, `authcid<TAB>password`. Blank lines and lines
 * whose first non-blank byte is '#' are ignored. The TAB is mandatory and is
 * the only separator, because the alternative -- splitting on whitespace -- makes
 * a password with a space in it unrepresentable, and a store that cannot hold a
 * passphrase is a store that pushes operators to weak ones. A record with no
 * TAB is malformed and fails the whole load rather than being skipped. */
sasl_store_t *sasl_store_load(const char *path);

/* An empty store, for a caller that wants to build one in memory. sasl_state_
 * machine() is that caller, and so is a future phase that loads credentials from
 * somewhere other than a file. Returns NULL only on allocation failure. */
sasl_store_t *sasl_store_new(void);

/* Add or replace the record for `authcid`. Returns 0, or -1 on a NULL/empty or
 * over-long authcid, an over-long password, or a full store. `password` is
 * COPIED. */
int sasl_store_add(sasl_store_t *store, const char *authcid, const char *password);

/* Number of records loaded. 0 on a NULL store, which is the honest answer for
 * "this node can authenticate nobody". */
size_t sasl_store_count(const sasl_store_t *store);

/* Release. Safe on NULL. A node calls this from server_shutdown(); LeakSanitizer
 * runs on the Linux CI job, so anything allocated here has to be freed there. */
void sasl_store_free(sasl_store_t *store);

/* ---------------------------------------------------------------------------
 * Verification
 * --------------------------------------------------------------------------- */

/* RFC 4616 PLAIN: `authzid NUL authcid NUL passwd`, from `len` bytes of decoded
 * payload. Returns 0 when all three fields were present and within their bounds,
 * -1 otherwise, and zeroes every output on any failure -- a caller that ignores
 * the return value gets empty strings rather than the previous call's bytes.
 *
 * `pass_cap` is the bound on the PASSWORD field, not on the whole payload, and
 * the caller chooses it; it is a parameter rather than a constant because
 * SASL_MAX_PASSWORD is the store's bound and a caller with a smaller buffer must
 * be refused rather than overflow. */
int sasl_plain_parse(const char *payload, size_t len,
                     char *authzid, size_t authzid_cap,
                     char *authcid, size_t authcid_cap,
                     char *passwd, size_t passwd_cap);

/* Verify `authcid`/`passwd` against `store`.
 *
 * Returns 1 only when the store holds a record for that authcid AND the
 * password matches. Everything else is 0, including a NULL store -- so a node
 * with no credential store authenticates nobody, which is the opposite of the
 * behaviour this module used to have.
 *
 * THE COMPARISON DOES NOT LEAK THE PASSWORD'S PREFIX. Every candidate in the
 * store is compared against the offered password in constant time, so a caller
 * cannot distinguish "wrong at byte 3" from "wrong at byte 300" by how long the
 * answer took, and a caller cannot distinguish "no such authcid" from "wrong
 * password" either: the walk does not stop at the match, and a miss is followed
 * by one comparison against a fixed dummy so the two cases cost the same. That
 * is the whole reason this is a loop with an accumulator rather than a
 * strcmp() and a return.
 *
 * THE COST, stated rather than hidden: a node with N credentials spends N
 * constant-time comparisons per AUTHENTICATE, and N is capped at
 * SASL_MAX_CREDENTIALS, so the worst case is 64 short comparisons on a
 * connection that has not registered. That is noise next to the base64 decode
 * that precedes it, and the alternative -- a hash of the password, so a lookup
 * could be O(1) -- is the hand-rolled-crypto outcome the header argues against. */
int sasl_plain_verify(const sasl_store_t *store,
                      const char *authzid, const char *authcid, const char *passwd);

/* base64 decode `inlen` bytes of `in` into `out`. Returns the decoded byte count,
 * or -1 on malformed input or insufficient capacity. Whitespace anywhere is
 * skipped, because clients wrap long AUTHENTICATE payloads and a server that
 * refuses a wrapped one refuses irssi. The output is NOT NUL-terminated; the
 * caller bounds it with the returned count, which is what makes a payload
 * containing a NUL -- which RFC 4616's format REQUIRES three of -- usable. */
long sasl_b64_decode(const char *in, size_t inlen, unsigned char *out, size_t cap);

/* ---------------------------------------------------------------------------
 * The observable state machine this module has always exposed
 * --------------------------------------------------------------------------- */

/* Zero `ctx`, set state to SASL_ABORTED and copy `mechanism` (truncating).
 * `ctx->store` is left NULL, which means "no store" and therefore "every
 * credential fails"; use sasl_set_store() to attach one. */
void sasl_init(sasl_ctx_t *ctx, const char *mechanism);

/* Attach the store a later step verifies against. NULL detaches it, which is the
 * same as never having had one. */
void sasl_set_store(sasl_ctx_t *ctx, const sasl_store_t *store);

/* Start the mechanism. Only valid from SASL_ABORTED, which it consumes; from any
 * other state it returns that state unchanged. */
sasl_state_t sasl_start(sasl_ctx_t *ctx);

/* Advance the exchange one step. Only valid from SASL_IN_PROGRESS.
 *
 * `server_data`/`len` are the RAW bytes the client sent: for AUTHENTICATE PLAIN
 * that is the base64 TEXT, and this function decodes it. On success the context
 * holds the decoded authzid/authcid, the state is COMPLETED, and nothing is
 * written to `client_out`/`out_len` (which are set to 0 when both are non-NULL).
 * On a malformed payload or a credential that does not verify, the state is
 * FAILED and `last_error` names which: SASL_ERR_* below.
 *
 * Returns the new state. A step in any other state returns that state unchanged,
 * so a caller that steps twice cannot be promoted to COMPLETED by the second
 * call -- which is exactly what the previous implementation did. */
sasl_state_t sasl_step(sasl_ctx_t *ctx, const char *server_data, size_t len,
                       char *client_out, size_t *out_len);

/* `last_error` values. Named so a refusal can say WHICH, since "authentication
 * failed" and "the payload was not base64" have different fixes for the client
 * and different ones for the operator. */
#define SASL_OK              0
#define SASL_ERR_NO_STORE   (-1)  /* no credential store: nobody can pass */
#define SASL_ERR_MECH      (-2)  /* a mechanism this node does not implement */
#define SASL_ERR_PAYLOAD   (-3)  /* not base64, or not three NUL-separated fields */
#define SASL_ERR_CREDENTIAL (-4) /* a well-formed credential that does not verify */

/* Force the context to SASL_ABORTED (a client sent AUTHENTICATE *, which is how
 * a client abandons the exchange) or SASL_FAILED, recording `error_code`. */
sasl_state_t sasl_abort(sasl_ctx_t *ctx, int error_code);
sasl_state_t sasl_fail(sasl_ctx_t *ctx, int error_code);

/* Read-only current state. */
sasl_state_t sasl_get_state(const sasl_ctx_t *ctx);

/* Drive the whole observable lifecycle over an in-memory store: a correct PLAIN
 * credential reaches COMPLETED, a wrong password reaches FAILED, an unknown
 * authcid reaches FAILED, a malformed payload reaches FAILED, and a context with
 * no store at all reaches FAILED. Returns 1 only when every path behaved as
 * documented, 0 otherwise.
 *
 * It prints nothing. The previous version printed "[observable]" lines on every
 * call, which meant a credential store's contents were being formatted into a
 * string on the authentication path -- the first thing anyone looks at when
 * asking where a password went. */
int sasl_state_machine(void);

#endif /* IRC_SASL_FRAMEWORK_H */
