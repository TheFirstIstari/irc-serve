/* reply.c -- see reply.h. The single place an outbound message to a client is
 * built and queued.
 *
 * ---------------------------------------------------------------------------
 * ONE ENFORCEMENT POINT, THREE ENTRY POINTS
 * ---------------------------------------------------------------------------
 * reply(), send_line() and send_pong() all end in emit_built(), and
 * emit_to_client() is the only thing in this file that calls server_queue(). The
 * peer-link refusal, the CLOSING refusal and the "no addressee" refusal all live
 * there, so there is no second copy of the invariant to keep in step and no way
 * for a new caller to reach the socket without passing it. A handler chooses a
 * numeric; it does not choose a destination.
 *
 * send_line() is Phase 4's addition and it is the same door, not a new one: a
 * channel broadcast is not a numeric, but it is still an outbound message to a
 * client and it must be refused for a peer target by exactly the same rule.
 */
#include "core/reply.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "core/message.h"
#include "core/cap.h"
#include "core/batch.h"
#include "core/fanout.h"

/* THE MERGED BUFFER'S ARITHMETIC, in three named pieces so that raising any bound
 * moves it rather than silently overflowing:
 *
 *   BATCH_TAG_MAX         one `batch=<ref>` pair INCLUDING its NUL -- the key, the
 *                         '=', and the widest reference CONN_MAX_BATCH_REF admits
 *   1u                    the ';' that joins it to whatever the caller already had
 *   FANOUT_TAG_BLOCK_MAX  that whatever: the `msgid`/`account` block fanout.c renders
 *
 * The whole of this is one line, and it is here rather than beside the buffer because
 * the first version of this file sized the CALLER's `bref` at CONN_MAX_BATCH_REF + 1
 * and dropped the tag at the boundary -- see BATCH_TAG_MAX's own comment. */

/* ---------------------------------------------------------------------------
 * Refusals
 * ------------------------------------------------------------------------ */

/* Report and count a refusal. Returns REPLY_REFUSED so every caller can
 * `return refuse(...)`.
 *
 * Deliberately NOT gated on s->trace. Every other [observable] line in the node
 * describes something the loop did, and the trace flag exists to turn those
 * off for a quiet run. This one describes something that should never happen;
 * it is a bug report, and a bug report that a flag can silence is not one. */
static int refuse(server_t *s, const conn_t *c, const char *code,
                  const char *reason)
{
    if (s != NULL) {
        s->n_reply_refused++;
    }
    printf("[observable] reply_refused: fd=%d code=%s reason=%s\n",
           (c != NULL) ? c->fd : -1, (code != NULL) ? code : "?", reason);
    return REPLY_REFUSED;
}

/* The one queueing site. Everything that can be wrong with an outbound
 * message to a client is refused here, before a byte is buffered. */
static int emit_to_client(server_t *s, conn_t *c, const char *code,
                          const char *line, size_t len)
{
    if (c == NULL) {
        return refuse(s, NULL, code, "no_target");
    }
    /* 3: numerics are never written to a peer link and never relayed. A peer
     * receives protocol messages and nothing else, because its framing layer
     * would parse a numeric as a command word. */
    if (c->kind == CONN_SERVER) {
        return refuse(s, c, code, "peer_target");
    }
    /* The loop has already dropped a CLOSING conn from the poll set, so
     * queued bytes would never be pumped; the reaper closes the fd instead. */
    if (c->state == CONN_CLOSING) {
        return refuse(s, c, code, "closing");
    }
    if (server_queue(s, c, line, len) != 0) {
        /* Already counted and already marked by server_queue(), which refuses
         * a saturated link rather than buffering it. Not a second count. */
        return REPLY_REFUSED;
    }
    return REPLY_OK;
}

/* Render one message through the Phase 1 formatter and hand it to the client
 * the call named. `params` holds the FULL parameter list including the target
 * and the trailing text; `code` is the command word. `prefix` NULL means the
 * node's own name, which is the rule for every numeric and for a PONG; a
 * client-originated broadcast passes the acting user's hostmask. `tags` is a
 * client-visible tag block WITHOUT the leading '@', or NULL for none. */
static int emit_built_ex(server_t *s, conn_t *c, const char *code,
                         const char *prefix,
                         const char *const *params, int nparams,
                         int force_colon, const char *tags)
{
    message_t m;
    /* IRC_MAX_LINE counts a legal line INCLUDING its terminator, and
     * message_format() reserves one byte for a NUL, so the render buffer needs
     * two more than that to hold a maximal line plus its CRLF. */
    char line[IRC_MAX_LINE + 2];
    /* The batch tag is PREPENDED to whatever tag block the caller already had, so
     * the merged form has to be a buffer rather than an in-place edit: a `msgid` and
     * an `account` block are rendered by fanout.c into a per-destination buffer that
     * is about to be freed, and "insert 71 bytes at the front of that" is not
     * something this function may do to a pointer it does not own.
     *
     * SIZED FROM THE TWO THINGS IT CAN HOLD. BATCH_TAG_KEY_MAX is
     * "batch=" (6) plus CONN_MAX_BATCH_REF; BATCH_TAG_SEP is the ';' that joins two
     * pairs; and the caller's own block is bounded by FANOUT_TAG_BLOCK_MAX, which is
     * the buffer fanout.c sizes. If a future caller of send_line_tagged() had a
     * larger block, this buffer would be the thing that has to move with it -- which
     * is why the size is written as an arithmetic expression over named pieces
     * rather than as a literal that looks generous. */
    char merged[FANOUT_TAG_BLOCK_MAX + BATCH_TAG_MAX + 1u];
    size_t len;

    /* ------------------------------------------------------------------------
     * `batch=<ref>` -- THE ONE PLACE A CLIENT-VISIBLE TAG IS ADDED
     * ------------------------------------------------------------------------
     * IT IS HERE AND NOT IN EACH EMITTER, and the reason is the one reply.c was
     * written for: this is the ONE place an outbound message to a client is built and
     * queued, so a `batch=` tag applied here is applied to a numeric, to a `353`, to a
     * `SETNAME` confirmation and to a `msgid`-stamped fan-out line alike. Applied at
     * the emitters, it would be applied to whichever emitters somebody remembered and
     * silently absent from the rest — and a client that opened a batch and then had
     * the numerics escape it would see a batch with holes in it.
     *
     * IT IS PREPENDED, so the order in the block is `batch` then whatever came next.
     * Tag order is not semantically meaningful in IRCv3 and nothing parses it, so
     * this is a readability choice: `batch=` first is the tag a reader is looking for.
     */
    if (c != NULL && c->kind != CONN_SERVER) {
        char bref[BATCH_TAG_MAX];

        if (batch_line_tag(c, bref, sizeof bref) == 1) {
            /* NO "batch=" PREFIX HERE. `batch_line_tag()` writes the WHOLE pair --
             * key, '=', value -- because batch.h says so and because a caller that
             * had to know the key name would be a second place to get it wrong. The
             * buffer's arithmetic is still in terms of the key, which is why
             * BATCH_TAG_KEY_MAX is a piece of that expression. */
            int n = snprintf(merged, sizeof merged, "%s", bref);

            if (n > 0 && (size_t)n < sizeof merged) {
                if (tags != NULL && tags[0] != '\0') {
                    int k = snprintf(merged + n, sizeof merged - (size_t)n, ";%s",
                                     tags);

                    if (k > 0 && (size_t)(n + k) < sizeof merged) {
                        tags = merged;
                    }
                    /* ELSE the merged block does not fit and `tags` is LEFT ALONE,
                     * which drops the `batch=` tag rather than the line. That is the
                     * deliberate choice, and it is the one reply.c's own header
                     * already makes about an oversized tag: the alternative is a
                     * refusal counted on n_reply_refused, the counter this project
                     * holds at zero because a non-zero value of it is a bug report.
                     * The buffer cannot in fact overflow -- see the arithmetic on its
                     * declaration -- so this arm is unreachable today and is written
                     * to be safe rather than to be believed. */
                } else {
                    tags = merged;
                }
            }
        }
    }
    if (message_build(&m, tags, (prefix != NULL) ? prefix : s->name, code,
                      params, nparams) != 0) {
        return refuse(s, c, code, "unbuildable");
    }
    len = message_format_ex(&m, line, sizeof line - 2u, force_colon);
    message_free(&m);
    if (len == 0) {
        /* A representable message that did not fit, or one holding a value
         * that cannot be represented in a non-final parameter position. Never
         * a partial line: message_format() renders all or nothing. */
        return refuse(s, c, code, "unrepresentable");
    }
    /* A `tags` BLOCK THAT DOES NOT FIT IS NOT A DEFENCE AND WAS NOT ADDED AS ONE.
     * The obvious worry about send_line_tagged() is a client's `msgid` pushing an
     * already-maximal line past IRC_MAX_LINE and the message being lost to a
     * decoration. It cannot happen, and the arithmetic is short enough to state
     * where it matters rather than guard against at run time:
     *
     *   3.2's cap on a client's own message is IRC_MAX_RELAY_LINE (8013), which
     *   is IRC_MAX_LINE minus IRC_MAX_TAG_OVERHEAD (179) -- and it is applied to
     *   the TEXT in msg_verbs.c BEFORE delivery, at the same place and for the
     *   same reason a render failure is not how a limit is discovered.
     *   The largest client-visible tag is IRC_MAX_MSGTAG (111) bytes, so the
     *   worst tagged line is 112 bytes over the cap and 67 bytes under
     *   IRC_MAX_LINE.
     *   Every other emission this node makes -- the numerics, a 353, a STOPIC
     *   relay, an SJOIN -- is bounded by its own field sizes (CHAN_MAX_TOPIC is
     *   255) and has no path to a maximal line.
     *
     * So the retry that would drop the tag and keep the message is DELIBERATELY
     * ABSENT rather than merely unnecessary: it would be unreachable today, and
     * this project does not keep code that defends against something it has just
     * shown cannot happen. If a future emission reaches here with a maximal line
     * and a tag, the refusal below is the correct answer and n_reply_refused --
     * the counter held at zero precisely because a non-zero value means a bug --
     * is the alarm. Whoever adds such an emission must charge the tag against
     * IRC_MAX_RELAY_LINE where fanout_line_fits() is applied. */
    /* RFC 1459 2.3: CRLF. message_format() terminates nothing, so this is
     * where the line terminator comes from. */
    line[len] = '\r';
    line[len + 1u] = '\n';
    return emit_to_client(s, c, code, line, len + 2u);
}

static int emit_built(server_t *s, conn_t *c, const char *code,
                      const char *prefix,
                      const char *const *params, int nparams)
{
    return emit_built_ex(s, c, code, prefix, params, nparams, 0, NULL);
}

/* <target> per RFC 2812 3.3: the client's nickname, or "*" when it does not
 * have one yet. A pointer into the conn_t, so it lives as long as the nick does
 * and reply() never has to copy it. */
static const char *reply_target(const conn_t *src)
{
    if (src != NULL && src->nick[0] != '\0') {
        return src->nick;
    }
    return "*";
}

/* ---------------------------------------------------------------------------
 * reply
 * ------------------------------------------------------------------------ */

int reply(server_t *s, conn_t *src, const char *code, const char *const *mid,
          size_t nmid, const char *fmt, ...)
{
    const char *params[IRC_MAX_PARAMS];
    char text[REPLY_TEXT_MAX];
    size_t n = 0;
    int want;
    va_list ap;
    int written;

    /* A NULL src is NOT handled here: it reaches emit_to_client(), which
     * refuses it as "no_target" alongside every other destination check. These
     * are arguments this function cannot use at all, which is a different fault
     * with a different name in the diagnostic. */
    if (s == NULL || code == NULL || code[0] == '\0' || fmt == NULL) {
        return refuse(s, src, code, "bad_args");
    }
    if (nmid > REPLY_MAX_MID) {
        /* target + mids + text must fit the 15-parameter cap. */
        return refuse(s, src, code, "too_many_params");
    }

    va_start(ap, fmt);
    written = vsnprintf(text, sizeof text, fmt, ap);
    va_end(ap);
    /* vsnprintf returns what it WOULD have written, so a non-negative result
     * at or above the buffer size means it was cut. 3.2 forbids delivering a
     * silently truncated parameter, so this is refused rather than sent. */
    if (written < 0 || (size_t)written >= sizeof text) {
        return refuse(s, src, code, "text_too_long");
    }

    want = (int)nmid + 2;
    params[n++] = reply_target(src);
    for (size_t i = 0; i < nmid; i++) {
        if (mid[i] == NULL) {
            return refuse(s, src, code, "bad_param");
        }
        params[n++] = mid[i];
    }
    params[n++] = text;

    return emit_built(s, src, code, NULL, params, want);
}

int send_line(server_t *s, conn_t *dst, const char *prefix,
              const char *command, const char *const *params, int nparams)
{
    if (s == NULL || command == NULL || command[0] == '\0') {
        return refuse(s, dst, command, "bad_args");
    }
    if (params == NULL && nparams != 0) {
        return refuse(s, dst, command, "bad_args");
    }
    if (nparams < 0 || nparams > IRC_MAX_PARAMS) {
        return refuse(s, dst, command, "too_many_params");
    }
    return emit_built(s, dst, command, prefix, params, nparams);
}

int send_line_tagged(server_t *s, conn_t *dst, const char *prefix,
                     const char *command, const char *const *params, int nparams,
                     const char *tags)
{
    if (s == NULL || command == NULL || command[0] == '\0') {
        return refuse(s, dst, command, "bad_args");
    }
    if (params == NULL && nparams != 0) {
        return refuse(s, dst, command, "bad_args");
    }
    if (nparams < 0 || nparams > IRC_MAX_PARAMS) {
        return refuse(s, dst, command, "too_many_params");
    }
    /* An empty block is refused rather than rendered as a bare '@': message_build()
     * rejects one, and asking it to would turn a caller bug into an "unbuildable"
     * report that names the wrong fault. An empty `tags` is not a tag block this
     * node can have produced -- irc_serve_msgid_tag() returns 0 rather than an
     * empty string for the same reason -- so it is a caller mistake worth naming. */
    if (tags != NULL && tags[0] == '\0') {
        return refuse(s, dst, command, "empty_tags");
    }
    /* The SAME door as send_line(), so the peer-target and CLOSING refusals and
     * the one queueing site are shared rather than restated. See the file header. */
    return emit_built_ex(s, dst, command, prefix, params, nparams, 0, tags);
}

/* ---------------------------------------------------------------------------
 * standard-replies
 * ---------------------------------------------------------------------------
 * IRCv3 defines THREE commands -- `FAIL`, `WARN` and `NOTE` -- all with the same
 * shape:
 *
 *     <type> <command> <code> [<context>...] :<description>
 *
 * and `ERROR` is NOT among them. It is a separate, older server command with no
 * relation to this specification, and its absence here is a fact rather than a
 * gap: the specification's introduction, its format section and its capabilities
 * section name `FAIL`, `WARN` and `NOTE` and nothing else, and the draft's own
 * history carried a fourth verb (`OK`) which was dropped before publication.
 * Emitting `ERROR` under this capability would be putting a command word on the
 * wire that no client negotiated this capability FOR.
 *
 * WHY ALL THREE ARE IMPLEMENTED WHEN ONLY `FAIL` HAS A PRODUCER. The three share
 * one format and one code registry, so implementing one and writing two more
 * later is exactly the kind of partial state that becomes an inconsistency, and
 * the cost of the other two is this function with a different `type`. What is NOT
 * done is inventing a producer: `WARN` is a non-fatal warning about a command and
 * `NOTE` an informational message about one, and this node has no command that
 * warns and none that notes. `cap.h` holds the same rule the capability table
 * does -- the NAME is advertised because the capability is real, and the two
 * commands without a producer are a named limit rather than a claim.
 */

/* The `<command>` field, which the specification makes REQUIRED: the command the
 * reply relates to, or `*` when it was not spawned by one. `*` rather than an
 * empty string and rather than this node's own name, because "not in the context
 * of a client command" is a different statement from "in the context of no command
 * in particular" and a client branching on the field can tell them apart. */
#define STD_COMMAND_NONE "*"

/* One emitter for all three types, and the ONLY place a standard-replies line is
 * built. The refusals are reply()'s, in the same order and for the same reasons:
 * a NULL destination, a peer link (3's federation invariant), a CLOSING target, a
 * code that does not fit, and a description that does not fit REPLY_TEXT_MAX.
 *
 * `nctx` IS COUNTED AGAINST THE SAME 15-PARAMETER CAP AS reply()'s `nmid`, with
 * the same arithmetic, because `<target> <command> <code>` has taken three slots
 * before either the context parameters or the description do. The specification's
 * `<context>` is optional and "not intended for end users, but for developers
 * gathering more information", so the honest bound is the wire's and not a smaller
 * invention. */
int reply_std(server_t *s, conn_t *src, const char *type, const char *command,
              const char *code, const char *const *ctx, size_t nctx, const char *fmt, ...)
{
    const char *params[IRC_MAX_PARAMS];
    char text[REPLY_TEXT_MAX];
    size_t n = 0;
    size_t want;
    va_list ap;
    int written;

    if (s == NULL || type == NULL || code == NULL || code[0] == '\0' ||
        fmt == NULL) {
        return refuse(s, src, type, "bad_args");
    }
    if (command == NULL || command[0] == '\0') {
        command = STD_COMMAND_NONE;
    }
    /* target + <command> + <code> + contexts + description. */
    want = nctx + 3u;
    if (want > (size_t)REPLY_MAX_MID) {
        return refuse(s, src, type, "too_many_params");
    }

    va_start(ap, fmt);
    written = vsnprintf(text, sizeof text, fmt, ap);
    va_end(ap);
    if (written < 0 || (size_t)written >= sizeof text) {
        return refuse(s, src, type, "text_too_long");
    }

    params[n++] = reply_target(src);
    params[n++] = command;
    params[n++] = code;
    for (size_t i = 0; i < nctx; i++) {
        if (ctx[i] == NULL) {
            return refuse(s, src, type, "bad_param");
        }
        params[n++] = ctx[i];
    }
    params[n++] = text;

    /* `emit_built()` rather than `emit_built_ex(..., 1, ...)`: the description is
     * colonned whenever the formatter needs to, which is the RFC 1459 2.3.1 rule
     * every other line here obeys. A `FAIL` whose description held a separator
     * gets its colon from the same code that colons a `461`'s, so the two shapes
     * agree about when a trailing parameter is marked rather than each having an
     * opinion. */
    return emit_built(s, src, type, NULL, params, (int)n);
}

/* The four numerics this node uses for MORE THAN ONE distinct refusal, and the
 * `FAIL` code each becomes. This is the whole of the migration table and it is
 * here rather than at the call sites for the reason this file is the one place a
 * numeric is emitted: a mapping transcribed per handler is a mapping with forty
 * copies to keep in step.
 *
 * THE RULE, in one sentence: a legacy numeric migrates where that numeric answers
 * more than one question ON THIS NODE, so the number alone cannot tell a client
 * which refusal happened.
 *
 *   417  PRIVMSG text too long | AWAY too long | SETNAME realname unacceptable |
 *        KICK reason too long.  Four refusals, one number.
 *   461  too few parameters AND too many -- and its text reads "Not enough
 *        parameters" in the too-many case too, so the number is ambiguous AND the
 *        text is wrong.  Two refusals, one number, one lie.
 *   482  not a channel operator (KICK, MODE, INVITE) | not an IRC operator
 *        (KNOCK) | the verb is disabled here (REGISTER, UNREGISTER).  Three
 *        refusals, one number -- and the KNOCK one is the sharpest, because
 *        "not a channel operator" and "not an IRC operator" differ by three
 *        letters and mean entirely different things.
 *   464  not an IRC operator | SASL authentication failed.  Two refusals, one
 *        number.
 *
 * EVERY OTHER NUMERIC STAYS, and the reason is the same rule pointed the other
 * way: `401`, `403`, `404`, `421`, `431`, `432`, `433`, `437`, `441`, `442`, `451`,
 * `472` and the rest each answer exactly ONE question on this node, so the number
 * is unambiguous, and replacing it would take away the name the client already
 * handles in exchange for a line it must now learn. The specification's own
 * introduction states the complaint this table answers -- "numerics themselves and
 * the mapping of numerics to names can be unclear or conflicting" -- and these
 * are the four where this node's own use makes them unclear.
 *
 * ON THE CODES. The specification says "implementers MUST use an existing code if
 * one is already defined", and the IRCv3 reply-code registry holds
 * `NEED_MORE_PARAMS` and `INVALID_PARAMS`. The rest of this table uses an `ERR_`
 * prefix, which is this node's marker for "a code that is ours and is not in the
 * registry" -- so a client switching on an unregistered code and an unregistered
 * code this node made up are never confused for one another.
 * `ERR_CHANOPRIVSNEEDED` and `ERR_NOPRIVILEGES` are RFC 1459/2812's own names for
 * 482 and 464, carried over because the numbers they replace were named after
 * them. */
typedef struct {
    const char *numeric;   /* the legacy code, as a caller writes it */
    const char *fail_code; /* what it becomes for a negotiating client */
} std_fail_map_t;

static const std_fail_map_t k_std_fail_map[] = {
    { "417", "ERR_INPUTTOOLONG" },
    { "461", "NEED_MORE_PARAMS" },
    { "482", "ERR_CHANOPRIVSNEEDED" },
    { "464", "ERR_NOPRIVILEGES" }
};

/* The `FAIL` code for `numeric`, or NULL when this node does not migrate it.
 *
 * An `override` wins over the table, and that is the whole reason it exists: each
 * numeric that answers several questions needs a DIFFERENT code per answer, and
 * the table can hold only one. A caller that means "too many parameters" passes
 * `TOO_MANY_PARAMS`; a caller that means "your realname held a byte this node will
 * not store" passes `ERR_INVALID_PARAM`. A caller that means nothing in
 * particular -- the overwhelming majority -- passes NULL and gets the table's
 * answer. */
static const char *std_fail_code(const char *numeric, const char *override)
{
    if (override != NULL && override[0] != '\0') {
        return override;
    }
    if (numeric == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < sizeof k_std_fail_map / sizeof k_std_fail_map[0]; i++) {
        if (strcmp(k_std_fail_map[i].numeric, numeric) == 0) {
            return k_std_fail_map[i].fail_code;
        }
    }
    return NULL;
}

int reply_refused(server_t *s, conn_t *src, const char *command, const char *fail_code,
                  const char *legacy, const char *const *mid, size_t nmid,
                  const char *fmt, ...)
{
    va_list ap;
    char text[REPLY_TEXT_MAX];
    const char *code;
    int written;
    int rc;

    /* THE WHOLE OF THIS FUNCTION IS ONE QUESTION, and it is asked before anything
     * else so that a caller cannot get it wrong by ordering: has this client
     * negotiated `standard-replies`?
     *
     * NO -- `reply()` with the legacy numeric, `mid`, `nmid` and the caller's own
     * format string. Byte-identical to what the caller would have got by calling
     * `reply()`. That is the guarantee, and it is STRUCTURAL rather than a matter
     * of each call site being careful: there is exactly one branch and it is the
     * old call, so there is nothing to be careful about.
     *
     * YES -- `reply_std()` with `FAIL`, the caller's command word, the mapped code,
     * the SAME `mid` list as the `<context>` parameters and the same text as the
     * `<description>`. The middle parameters carry over unchanged because they name
     * the thing the refusal is about (a channel, a nickname) and that is exactly
     * what `<context>` is for.
     *
     * A NULL `fail_code` AND an unmapped `legacy` falls through to `reply()` too,
     * so this function is SAFE at any call site including one whose numeric this
     * node does not migrate. That is deliberate: a handler should be able to reach
     * for the one refusal entry point without first consulting a list that lives
     * in another file, and a caller that means to migrate and mistypes the numeric
     * gets the legacy answer rather than a `FAIL` carrying a code nobody can act
     * on.
     *
     * `code` HOLDS THE MAPPED ANSWER AND IS WHAT IS PASSED ON, which sounds like
     * stating the obvious and was the second version of this function's bug: it
     * called std_fail_code() to DECIDE whether to migrate and then passed
     * `fail_code` -- the caller's OVERRIDE, which is NULL at every site that wanted
     * the table's answer -- straight to reply_std(). reply_std() then refused the
     * line with `bad_args`, which is its refusal for an empty code, and the client
     * got NOTHING: no 417, no `FAIL`, and a `reply_refused:` line on the node's own
     * output for a refusal that had an answer. `test_standard_replies.c` caught it
     * as a timeout waiting for `FAIL AWAY ERR_INPUTTOOLONG` on a connection that
     * had negotiated the capability and was owed one. Resolving the code once, into
     * a name, is what makes the mapping and the emission impossible to disagree.
     *
     * THE TEXT IS RENDERED ONCE, AT THE TOP, AND BOTH BRANCHES ARE HANDED IT WITH
     * `"%s"`. That is not an optimisation and it is not tidiness -- it is the only
     * way a variadic wrapper can work, and the wrong version of it is a defect this
     * project has now had once: an earlier version of this function passed the
     * caller's `fmt` straight through as the ARGUMENT of a literal `"%s"`, which
     * drops the caller's own arguments and puts the format string itself on the
     * wire. `test_choper` caught it as `:irc.test 464 * :SASL authentication
     * failed: %s` -- a refusal that had lost the one word which said whether the
     * store was missing or the password was wrong. `va_list` cannot be forwarded
     * to another variadic function in this dialect, so rendering once and handing
     * the result over is the fix rather than a workaround, and it also guarantees
     * the two renderings are the same STRING, which is the property
     * "byte-identical for a client that negotiated nothing" is about.
     */
    if (s == NULL || legacy == NULL || legacy[0] == '\0' || fmt == NULL) {
        return refuse(s, src, legacy, "bad_args");
    }

    va_start(ap, fmt);
    written = vsnprintf(text, sizeof text, fmt, ap);
    va_end(ap);
    if (written < 0 || (size_t)written >= sizeof text) {
        /* The same refusal reply() raises for the same text, and for the same
         * reason: 3.2 forbids delivering a silently shortened parameter. */
        return refuse(s, src, legacy, "text_too_long");
    }

    code = std_fail_code(legacy, fail_code);
    if (cap_standard_replies_enabled(src) == 0 || code == NULL) {
        return reply(s, src, legacy, mid, nmid, "%s", text);
    }

    rc = reply_std(s, src, "FAIL", command, code, mid, nmid, "%s", text);
    /* reply_std()'s outcome is the CALLER's. A `FAIL` that would not render is a
     * refusal counted on n_reply_refused exactly as a numeric's would be, and
     * returning REPLY_OK after one would make this wrapper the one place on the
     * reply path that can fail without saying so. */
    return rc;
}

/* ---------------------------------------------------------------------------
 * send_pong
 * ------------------------------------------------------------------------ */

int send_line_colon(server_t *s, conn_t *dst, const char *prefix,
                    const char *command, const char *const *params, int nparams)
{
    if (s == NULL || command == NULL || command[0] == '\0') {
        return refuse(s, dst, command, "bad_args");
    }
    if (params == NULL && nparams != 0) {
        return refuse(s, dst, command, "bad_args");
    }
    if (nparams < 0 || nparams > IRC_MAX_PARAMS) {
        return refuse(s, dst, command, "too_many_params");
    }
    return emit_built_ex(s, dst, command, prefix, params, nparams, 1, NULL);
}

int send_pong(server_t *s, conn_t *src, const char *token)
{
    const char *params[2];
    const char *body;

    if (s == NULL) {
        return refuse(s, src, "PONG", "bad_args");
    }
    /* RFC 1459 2.4: a PING with no argument is answered with the server name,
     * and an empty trailing parameter would render as a bare ':' and read back
     * as an empty token -- not the same thing to the client doing the
     * comparison. */
    body = (token != NULL && token[0] != '\0') ? token : s->name;
    params[0] = s->name;
    params[1] = body;
    return emit_built(s, src, "PONG", NULL, params, 2);
}
