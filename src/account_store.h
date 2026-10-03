/* account_store.h -- the ACCOUNT REGISTRY: which account names EXIST, and the
 * password each one is held under.
 *
 * Authority: docs/SERVER_DESIGN.md 2.1 (scoped identity, and the second axis
 * this adds), 5 (the credential-store discipline this mirrors), and
 * 7/Phase 10.1. The IRCv3 `account-registration` specification is the client-side
 * counterpart and is REFUSED here rather than implemented; the argument is in
 * docs/SERVER_DESIGN.md and at handle_register()/handle_unregister() in
 * core/commands.c.
 *
 * ---------------------------------------------------------------------------
 * WHAT AN ACCOUNT IS, IN ONE PARAGRAPH, BECAUSE IT DID NOT EXIST YESTERDAY
 * ---------------------------------------------------------------------------
 * An account is a NAMED IDENTITY THAT OUTLIVES A SOCKET. Everything this tree
 * had before this file authenticated a CONNECTION: SASL PLAIN proves that a
 * socket holds a password, and the proof dies with the socket, so `c->sasl` is
 * a fact about a connection and nothing else. An account is the other thing --
 * the thing that is still there after the client disconnects, reconnects,
 * reconnects elsewhere, and is still the same person. That is why it needs a
 * store at all: a registry is what makes the name mean something to anybody but
 * the socket that proved it.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS IS A SEPARATE FILE FROM THE CREDENTIAL STORE, STATED AS A DECISION
 * ---------------------------------------------------------------------------
 * It is the same KIND of thing and it is a DIFFERENT file, and the reason is
 * that the two have different lifetimes and different blast radii:
 *
 *   sasl_store_t  WHO MAY AUTHENTICATE HERE. One row per authcid. A client that
 *                 authenticates as `alice` gets the same treatment whether or
 *                 not a row for `alice` exists -- SASL PLAIN grants nothing on
 *                 this node at all (see sasl_framework.h), so the credential
 *                 store is a gate and nothing more. Its rows can be rewritten
 *                 freely: delete one and that login stops working, and nobody
 *                 else is affected.
 *
 *   account_store_t  WHICH ACCOUNTS EXIST. A row is a statement about a name,
 *                 not about a login: `alice` is an account whether or not she
 *                 has ever connected, and the row is what `account-tag` will
 *                 eventually have to be true against. That makes an accidental
 *                 deletion a different kind of event from a failed login -- it
 *                 is the loss of an identity, not the loss of access -- and the
 *                 two do not belong in one file where one `grep` and one edit
 *                     reaches both.
 *
 * The cost is stated rather than hidden: an operator configures TWO files, they
 * are read at the same point in main() and in the same pre-loop phase 3.4
 * requires, and the two must agree or authentication stops (see
 * account_lookup()'s contract). The alternative -- one file with a per-record
 * "this is also an account" flag -- was rejected because it makes the FILE's
 * meaning a property of a byte inside a line, and a credential file whose rows
 * mean different things depending on a flag is a file whose blast radius is one
 * bad edit wide. Two files, two blast radii.
 *
 * ---------------------------------------------------------------------------
 * THE FORMAT, AND WHY IT IS THREE TAB-SEPARATED FIELDS
 * ---------------------------------------------------------------------------
 * One record per line:
 *
 *     <name> TAB <password> TAB <created>
 *
 *   name      the account name. See account_store.h's ACCOUNT_MAX_NAME for the
 *             bound and for why this module does not impose a CHARSET rule.
 *   password  the secret. A TAB is impossible in it because a TAB is the
 *             separator, and a SPACE is possible and is why the separator is a
 *             TAB: a registry that cannot hold a passphrase pushes operators
 *             towards weak ones, which is exactly the argument
 *             sasl_store_load() makes for the same choice.
 *   created   integer seconds since the Unix epoch: when the operator created
 *             the record. It is the one piece of registration metadata this
 *             module holds, and the reason it is HERE rather than "a field for
 *             later" is that it is what makes a store file reviewable: an
 *             operator can see at a glance which rows are old. See the block on
 *             EMAIL below for the metadata that is deliberately absent.
 *
 * A LINE WITH FEWER THAN THREE FIELDS IS A REFUSAL, not a record with defaults,
 * for the reason sasl_store_load() gives: a registry that loads half its file
 * is a node that will refuse half its accounts, and the half that fails is
 * discovered by a user being told their account does not exist. A line with
 * MORE than three is also a refusal, because "name TAB password TAB 1700000000
 * TAB extra" is a file written by something that does not mean what this module
 * means, and guessing which three fields are the ones is how a password ends up
 * in a timestamp column.
 *
 * EMAIL IS NOT STORED, and that is a decision rather than an omission.
 * `account-registration` defines REGISTER's email parameter, and its whole
 * purpose is a verification mail this node cannot send: there is no MTA, no
 * outbound queue, and 3.4 forbids doing either inside the event loop. So an
 * address in the store would be personal data with nothing behind it that could
 * ever act on it -- a liability, not a feature -- and it would make the registry
 * a second secret store for a secret nothing consumes. When this node has a mail
 * path, adding the column is a format change with a migration; adding it now
 * would be a format with a permanent hole in it.
 *
 * ---------------------------------------------------------------------------
 * THE FILE IS A SECRET STORE, AND IS CHECKED AS ONE
 * ---------------------------------------------------------------------------
 * The password column makes this a file of passwords, so every control
 * sasl_store_load() applies applies here too, and the reasoning is unchanged and
 * restated here because the discipline has to be visible AT BOTH readers rather
 * than in one of them:
 *
 *   - `fopen(path, "re")` with the 'e' flag (O_CLOEXEC), then `fstat()` on the
 *     DESCRIPTOR. stat()-then-open was a real TOCTOU race on a file of
 *     passwords and is not repeated here.
 *   - `S_ISREG`. A FIFO or a device is not a registry.
 *   - The group and world permission bits must be CLEAR. A registry any other
 *     account on the host can read is a list of passwords, and this is a
 *     refusal rather than a warning.
 *
 * There is NO PARTIAL SUCCESS: a store that loaded half its file is refused
 * whole, and the node comes up with NO ACCOUNT STORE rather than with a partial
 * one. That state is the honest one, and it is the same state as "the operator
 * configured nothing" -- which is precisely why core/account.c's predicate does
 * not need to ask about it.
 */
#ifndef IRC_ACCOUNT_STORE_H
#define IRC_ACCOUNT_STORE_H

#include <stddef.h>

/* Bounds on the account registry. Constants rather than configuration, and the
 * reason is the one sasl_framework.h states for the credential store's: this is
 * loaded from a path an operator names, and a store whose size depends on a
 * number read from the same file is a store whose bound is the file. */
#define ACCOUNT_MAX_NAME      63   /* conn_t::account's bound minus one, and the
                                    * derivation is the short version of "the
                                    * largest value that can reach it": a
                                    * connection's account is set from a SASL
                                    * authcid, and SASL_MAX_AUTHCID is 63, so a
                                    * WIDER field could not be filled by anything
                                    * this node accepts. See conn_t's block in
                                    * core/connection.h for the rest. */


/* ---------------------------------------------------------------------------
 * WHAT MAKES AN ACCOUNT NAME VALID, which is more than "not empty"
 * ---------------------------------------------------------------------------
 * `account_name_wire_safe()` is the whole of it, and it is here rather than in
 * core/account.c because the KEY SPACE is this module's business: a name this
 * predicate refuses is a name no connection can ever be logged in as, whatever the
 * connection layer does with the string it is handed.

 * `*` is ACCEPTED, and that is the exception the whole rule is built around: `*`
 * is how both `extended-join` and `account-notify` spell "this user has no account",
 * so a registry must be able to hold the one name the protocol reserves for the
 * absence of one.

 * THE RULE IS RENDERABILITY AND NOT A CHARSET. There is deliberately no list of
 * "characters an account name may contain", because the list this node would need
 * is the union of what every renderer downstream can represent, and that union is
 * not one list:

 *   - a MESSAGE TAG escapes ';', ':', '\\', SP, CR and LF, so a name holding them
 *     is representable in `account-tag` -- which is why the tag renderer escapes
 *     rather than refusing.
 *   - a MESSAGE PARAMETER can escape NOTHING. 3.2 refuses SP, HTAB, CR and LF in
 *     any parameter, and refuses a value that needs the ':' marker anywhere but the
 *     final position. So a name holding one of those cannot be written into a JOIN
 *     echo, into an SJOIN, or into 330 RPL_WHOISACCOUNT at all.
 *
 * The second list is the binding one, and it is why this was not added until
 * Phase 10.3 even though it was already true: 330 has carried the account as a
 * MIDDLE parameter since Phase 10.1, so the exposure was there first and this
 * phase simply gave the name three more parameter positions to be wrong in.
 *
 * AND THE NAME MUST ALSO FIT, which is a third rule rather than a fourth and is
 * the one that took a peer to find. "Renderable" is about the BYTES; a name is
 * also STORED, in a field of ACCOUNT_MAX_NAME bytes -- conn_t::account,
 * chan_remote_t::account and burst_member_t::account are all that wide and
 * ACCOUNT_MAX_NAME is defined as conn_t::account's bound minus one. A name longer
 * than that is one this node cannot hold, whatever it is made of.
 *
 * With only the byte rule, the two LOCAL callers were safe (both bounded the
 * length separately) and the two PEER-side callers were not: channel.c's
 * copy_bounded() truncated an over-long SJOIN account into the roster, and
 * federation/burst.c's burst_copy() refused it -- leaving a slot of a realloc'd
 * array that nothing zeroes holding whatever the allocator had left there. So the
 * length is HERE rather than at either receiver, which is the argument this
 * predicate's own header makes: a name it refuses is a name no field can hold,
 * whichever of the two a caller happened to notice.
 *
 * THE COST, stated rather than implied: an operator cannot create an account whose
 * name holds a space or whose name runs past ACCOUNT_MAX_NAME, and a registry file
 * holding one is REFUSED record by record rather than loaded with a name this node
 * cannot show anybody. That is a restriction, and the alternative is an account
 * that exists and is unreportable.
 */
int account_name_wire_safe(const char *name);
#define ACCOUNT_MAX_PASSWORD  128   /* SASL_MAX_PASSWORD, deliberately the same
                                    * bound and for the same reason: this is the
                                    * account's own secret, the two stores are
                                    * configured by one operator in one
                                    * directory, and two different password
                                    * length limits on the same host is one
                                    * thing an operator has to discover the hard
                                    * way. RFC 4013's PLAIN has no length limit
                                    * either, so this is ours and is stated. */
#define ACCOUNT_MAX_RECORDS   64   /* an operator's registry is a small set; 64
                                    * records at ~200 bytes is ~13 KB, and the
                                    * per-login walk is a linear scan rather
                                    * than a search algorithm anyone should
                                    * build for a table this size */
#define ACCOUNT_MAX_LINE      512  /* one record in the file, NUL included */

/* An opaque registry. Declared here and defined in account_store.c for the same
 * reason sasl_store_t is: a caller cannot build one by laying out fields, so the
 * bounds above are the bounds rather than a suggestion. */
typedef struct account_store account_store_t;

/* ---------------------------------------------------------------------------
 * The registry
 * --------------------------------------------------------------------------- */

/* Load `path`. Returns NULL on ANY failure -- unreadable, not a regular file,
 * group- or world-accessible, malformed, or with no usable record (and, because
 * a full store refuses further records, a file with more than ACCOUNT_MAX_RECORDS
 * of them) -- and prints one [observable] line naming the reason. NULL means
 * "this node has no account registry", which is the same state as "the operator
 * configured none" and which core/account.c treats identically: see
 * ACCOUNT IDENTITY BELOW. */
account_store_t *account_store_load(const char *path);

/* An empty registry, for a caller that wants to build one in memory. Returns
 * NULL only on allocation failure. */
account_store_t *account_store_new(void);

/* Add or replace the record for `name`. Returns 0, or -1 on a NULL/empty
 * `name`, an over-long name or password, a name or password containing a TAB,
 * or a full store. Both strings are COPIED. The timestamp is a C long rather
 * than a string because it is a NUMBER, and a number kept as a string is a
 * number two comparisons from being compared wrongly.
 *
 * `created` is the registration metadata this module holds and is REQUIRED --
 * see the format block above for why a two-field record is a refusal rather
 * than a record with a default. A caller with no timestamp to offer passes 0,
 * which is "the epoch" and is honest about being unknown rather than false:
 * it cannot be confused with a real creation time because it is not one.
 *
 * THERE IS NO account_store_has(), and the absence is a decision rather than an
 * oversight. "Does this account exist" is a weaker question than "does this
 * account exist AND is this its password", verify() below answers the stronger
 * one, and a second entry point that answers the weaker one over the same table
 * is a second place for the two answers to disagree -- which is the shape of
 * this tree's issue #102/#103, where a registry had one index updated on one
 * path and another on another. One question, one function. */
int account_store_add(account_store_t *store, const char *name,
                      const char *password, long created);

/* Does `name` exist AND is `password` the password held for it?
 *
 * Returns 1 only for both. Everything else is 0, including a NULL registry or a
 * NULL/empty name -- so a node with no registry passes no account claim, which
 * is the fail-closed direction and the whole of what makes "no store" safe.
 *
 * THE COMPARISON DOES NOT LEAK THE PASSWORD'S PREFIX, for the reason
 * sasl_plain_verify() gives: every record is walked and every candidate is
 * compared, the walk does not stop at the match, and a miss is followed by one
 * comparison against a fixed dummy, so "no such account" and "wrong password"
 * cost the same and neither costs a function of WHERE the difference is. The
 * cost, stated rather than hidden: one bounded linear scan of at most
 * ACCOUNT_MAX_RECORDS constant-time comparisons per login, which is noise
 * next to the base64 decode that precedes it. */
int account_store_verify(const account_store_t *store, const char *name,
                         const char *password);

/* Number of records loaded. 0 on a NULL registry, which is the honest answer for
 * "this node holds no account registry". */
size_t account_store_count(const account_store_t *store);

/* Release. Safe on NULL. A node calls this from server_shutdown();
 * LeakSanitizer runs on the Linux CI job, so anything allocated here has to be
 * freed there.
 *
 * THE PASSWORDS ARE OVERWRITTEN BEFORE THE MEMORY IS RELEASED, and the comment
 * says why in the same words sasl_store_free() uses: free() does return the
 * memory, but the allocator reuses the buffer for the next node of the same
 * size, and a password still legible there outlives the record that named it.
 * The write pass goes through a `volatile` pointer so the compiler cannot elide
 * the stores as dead, which is the whole reason it is not a memset(). The cost
 * is one pass over ~13 KB on a path that runs once per process. */
void account_store_free(account_store_t *store);

/* ---------------------------------------------------------------------------
 * THE ONE BOUNDARY BETWEEN THE STORE AND THE CONNECTION
 * ---------------------------------------------------------------------------
 * core/connection.h owns the connection-side field and core/account.c owns the
 * predicate, so this header is deliberately NOT where the answer to "is this
 * connection logged in" lives -- a caller must go through one predicate rather
 * than be handed a string and asked to compare it. See core/account.h. */

#endif /* IRC_ACCOUNT_STORE_H */
