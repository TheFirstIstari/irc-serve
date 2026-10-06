/* batch.c -- see batch.h. The `batch` capability's client-facing half: the `BATCH`
 * verb, and the `@`/`+` reference tags that name a response or suppress it.
 *
 * Every comment that argues for a decision lives in batch.h, which is where a reader
 * looks for the module's contract. What is here is the code and the handful of
 * choices that are about THIS file rather than about the module.
 */
#include "core/batch.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "core/cap.h"
/* For conn_text_logsafe() and CONN_LOG_FIELD_MAX -- the log-injection set, applied
 * to the reference tags this file renders. */
#include "core/connection.h"
#include "core/reply.h"

/* ---------------------------------------------------------------------------
 * The character class
 * ---------------------------------------------------------------------------
 * ASCII letters, ASCII digits and '-', and nothing else. Written out rather than
 * `isalnum()` for the reason batch.h gives: this is a locale-independent wire
 * grammar, and `isalnum()` is not one. */
static int ref_byte_ok(char ch)
{
    return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
           (ch >= '0' && ch <= '9') || ch == '-';
}

int batch_ref_valid(const char *ref)
{
    size_t n;

    if (ref == NULL || ref[0] == '\0') {
        return 0; /* an empty reference names nothing */
    }
    n = strlen(ref);
    /* THE LENGTH BOUND IS CONN_MAX_BATCH_REF AND NOT `sizeof conn_t::batch_ref`
     * arithmetic repeated here. One declaration in connection.h owns it, which is
     * the same reason `cap.c` derives its names rather than writing them out. */
    if (n > (size_t)CONN_MAX_BATCH_REF) {
        return 0;
    }
    for (size_t i = 0; i < n; i++) {
        if (ref_byte_ok(ref[i]) == 0) {
            return 0;
        }
    }
    return 1;
}

/* ---------------------------------------------------------------------------
 * FINDING THE REFERENCE IN THE INBOUND BLOCK, and the sigil is PART OF THE KEY
 * ---------------------------------------------------------------------------
 * `@drop1` on the wire is a tag whose key is the four characters `@drop1`; the `@` is
 * NOT a marker, and `m->tags` holds the block WITHOUT it. `message_tag_get()` takes a
 * literal key, so it cannot answer "the first pair whose key starts with `@`" -- and
 * passing `"@"` to it searches for a pair whose key is exactly one character, which
 * is never what a client sends. The first version of this function did exactly that,
 * and `@` silently did nothing; `test_batch.c` case 4 caught it as a window holding
 * five lines where the test required one.
 *
 * THE SCAN WALKS THE BLOCK WITH THE PARSER'S OWN RULES: pairs are separated by ';', a
 * key runs to that pair's own '=' or to the next separator, and a pair with no '=' has
 * an empty value. Nothing here re-validates, because `message_parse_n()` has already
 * refused the line outright if the block was malformed -- so the only job left is to
 * walk it, and a walk that could disagree with the parser would be a walk that could
 * not be checked.
 *
 * THE VALUE IS TAKEN VERBATIM AND NOT UNESCAPED, which is correct rather than an
 * omission: the reference character class is ASCII letters, digits and '-', and none
 * of IRCv3's five escapable bytes is in it. A value that needed unescaping could not
 * be a legal reference, so `batch_ref_valid()` rejects it -- which is the answer any
 * implementation that followed the class would give.
 *
 * THE FIRST MATCH WINS for each sigil. The specification gives a reference tag no
 * multiplicity, so a block carrying two `@` tags has no defined meaning and taking the
 * first is arbitrary; it is recorded here rather than left for a reader to infer.
 *
 * THE BUFFER IS THE CONNECTION'S OWN WIDTH, so a legal reference always fits, and a
 * wider one -- which cannot be legal, because `CONN_MAX_BATCH_REF` IS the cap -- is
 * refused here rather than truncated into a different reference. Truncating would be
 * 3.2's forbidden "deliver a shortened value" and would tag the response with a batch
 * nobody opened.
 */
static int find_reference(const message_t *m, char sigil, char *out, size_t cap)
{
    const char *p;

    if (m == NULL || m->tags == NULL || out == NULL || cap == 0u) {
        return 0;
    }
    p = m->tags;
    while (*p != '\0') {
        const char *key = p;
        const char *vend;
        size_t klen;

        while (*p != '\0' && *p != ';' && *p != '=') {
            p++;
        }
        klen = (size_t)(p - key);
        /* SKIP PAST THIS PAIR'S VALUE, if it has one. A pair's own '=' cannot be
         * inside another pair's value -- the parser has already refused a value
         * containing a raw ';' -- so running to the next ';' is exact. */
        if (*p == '=') {
            p++;
            while (*p != '\0' && *p != ';') {
                p++;
            }
        }
        vend = p;
        if (klen >= 2u && key[0] == sigil) {
            size_t vlen = klen - 1u;

            if (vlen >= cap) {
                return 0;
            }
            memcpy(out, key + 1, vlen);
            out[vlen] = '\0';
            return 1;
        }
        p = (*vend == ';') ? vend + 1 : vend;
    }
    out[0] = '\0';
    return 0;
}

/* ---------------------------------------------------------------------------
 * The dispatch hook
 * ---------------------------------------------------------------------------
 * ONE SIGIL AND IT IS `+`. The retired `reference-tags` specification also defined
 * `@<ref>` as "send the response nowhere", and it is NOT implemented: `@` is the
 * tag-block MARKER, this parser consumes exactly one of them, and both candidate
 * spellings were checked against `message_parse_n()` rather than reasoned about --
 *
 *     "@ref WHOIS bob"     parses;  m->tags is "ref", a valueless tag
 *     "@@ref WHOIS bob"    the parser REFUSES the line outright
 *
 * -- so there is no encoding a conformant parser preserves and the drop form has
 * nowhere to live. `+` is the sigil the modern grammar keeps INSIDE the key
 * (`<key> ::= [ <client_prefix> ] ...`, `client_prefix ::= '+'`), which is why it is
 * the one implemented, and why the wire form is `@+ref`.
 *
 * AN ILLEGAL REFERENCE IS IGNORED, and that is a decision rather than an oversight.
 * The specification defines the character class and gives no numeric for a tag that
 * violates it, so there is nothing to answer with that a client could act on -- and a
 * client that has been told the tag is `batch` has been told it will be applied, not
 * that it will be validated. What is NOT ignored is the risk: an invalid reference
 * must not become a stored one, so the connection's batch state is left exactly as it
 * was, and the reason goes to the observable output where §3.4's output can find it.
 *
 * THE COST, named: a client that sends `+bad.ref WHOIS x` gets an untagged response
 * and no complaint. That is worse than a `421` in a diagnostic sense and it is the
 * right answer in an operational one -- the alternative is a numeric whose only
 * possible meaning is "your tag was malformed", which is a new numeric §4.4 would then
 * have to list.
 *
 * AND IT IS IGNORED RATHER THAN TREATED AS `@`, which is the difference between a
 * mis-tagged response and a LOST one: a client whose `+` reference was rejected still
 * WANTS its response.
 */
static void note_reference(conn_t *c, const message_t *m, char sigil)
{
    char ref[CONN_MAX_BATCH_REF + 1];

    if (find_reference(m, sigil, ref, sizeof ref) == 0) {
        return; /* absent, which is the common case and not an error */
    }
    if (batch_ref_valid(ref) == 0) {
        /* MEASURED, NOT STRIPPED. This is the interesting half of the two `ref=`
         * lines in this file: `ref` is here precisely because it FAILED
         * `batch_ref_valid()`, so its whole value is what the client got wrong --
         * a near-miss like `my_ref` is the diagnostic, and stripping or withholding
         * the whole string would throw it away. What is withheld is only the part
         * a terminal would execute.
         *
         * The other `ref=` line further down takes `m->params[0] + 1`, which is
         * unbounded, and both are handled the same way for the same reason: the
         * bytes are measured with the shared predicate rather than filtered with a
         * second copy of the rule.
         *
         * EVERY OTHER REFERENCE THIS FILE PRINTS IS ALREADY SAFE, and it is worth
         * naming so the next reader does not re-audit them: `c->batch_ref` and
         * `c->batch_type` are written only after `batch_ref_valid()` passes, and
         * `wanted=`/`batch_close: ref=` print a `ref` that passed the same test on
         * the line above. The grammar is alnum and '-', so none of them can hold a
         * byte from the set. */
        char shown[CONN_LOG_FIELD_MAX + 1u];
        const char *shown_ref = (ref[0] != '\0') ? ref : "";

        (void)conn_text_logsafe(shown, sizeof shown, shown_ref);
        printf("[observable] batch_ref_refused: fd=%d sigil=%c ref=%s ref_len=%zu "
               "ref_bad_bytes=%zu reason=ILLEGAL\n",
               c->fd, sigil, shown, strlen(shown_ref),
               conn_text_bad_count(shown_ref));
        return;
    }
    /* AN OPEN BATCH MAKES A `+` A NO-OP HERE, and this is where "one batch at a time"
     * is enforced for the reference form: while `batch_ref` is non-empty every line
     * already carries it, so storing a one-shot would either be unreachable or would
     * race the open batch for the same line. */
    if (c->batch_ref[0] != '\0') {
        return;
    }
    memcpy(c->batch_once, ref, strlen(ref) + 1u);
}

void batch_begin_command(conn_t *c, const message_t *m)
{
    if (c == NULL || m == NULL) {
        return;
    }
    note_reference(c, m, '+');
}

int batch_line_tagged_inbound(const message_t *m)
{
    const char *p;

    if (m == NULL || m->tags == NULL) {
        return 0;
    }
    p = m->tags;
    while (*p != '\0') {
        const char *key = p;
        size_t klen;

        while (*p != '\0' && *p != ';' && *p != '=') {
            p++;
        }
        klen = (size_t)(p - key);
        if (*p == '=') {
            p++;
            while (*p != '\0' && *p != ';') {
                p++;
            }
        }
        /* COMPARED CASE-INSENSITIVELY, because IRCv3 tag KEYS are case-insensitive and
         * a client that wrote `@BATCH=` has written the same tag. */
        if (klen == 5u && strncasecmp(key, "batch", 5u) == 0) {
            return 1;
        }
        p = (*p == ';') ? p + 1 : p;
    }
    return 0;
}

/* ---------------------------------------------------------------------------
 * The reply hook
 * ---------------------------------------------------------------------------
 * IT IS NOT `const conn_t *` AND THAT IS THE POINT. Consuming a one-shot reference IS
 * this function's job; taking a `const` pointer and mutating through it would be a
 * lie about the effect that the signature exists to make visible.
 */
int batch_line_tag(conn_t *dst, char *out, size_t cap)
{
    int n;

    if (dst == NULL || out == NULL || cap == 0u) {
        return 0;
    }
    out[0] = '\0';
    /* AN OPEN BATCH FIRST, and it consumes nothing: while a batch is open EVERY line
     * this connection receives is inside it, which is what the client asked for by
     * opening one. */
    if (dst->batch_ref[0] != '\0') {
        n = snprintf(out, cap, "batch=%s", dst->batch_ref);
        return (n > 0 && (size_t)n < cap) ? 1 : 0;
    }
    /* THEN THE ONE-SHOT, consumed by the line that carries it. A client that named a
     * batch for one response gets `batch=` on the first line of that response and not
     * on the rest -- which is what `draft/multiline`'s use needs and what makes `+`
     * mean anything outside an open batch, which is the case a client grouping a
     * single command's response actually hits. */
    if (dst->batch_once[0] != '\0') {
        n = snprintf(out, cap, "batch=%s", dst->batch_once);
        dst->batch_once[0] = '\0';
        return (n > 0 && (size_t)n < cap) ? 1 : 0;
    }
    return 0;
}

const char *batch_open_ref(const conn_t *c)
{
    if (c == NULL) {
        return "";
    }
    return c->batch_ref;
}

/* ---------------------------------------------------------------------------
 * BATCH
 * ---------------------------------------------------------------------------
 * Two forms and one rule: ONE BATCH AT A TIME PER CONNECTION.
 *
 * THE REFERENCE TAG AND THE TYPE ARE COPIED, NEVER REFERENCED. `m->params[i]` points
 * into the `message_t`'s own heap, and the connection outlives the message by an
 * enormous margin -- a client can hold a batch open for hours. A stored POINTER is a
 * use-after-free the moment the parser frees the buffer, and it is the kind that
 * survives a whole test suite, because nothing reads it until the free has happened
 * and the allocator has reused the bytes. Both `memcpy`s below write into fixed-size
 * `conn_t` fields, so there is nothing to free and nothing to leak; the test for
 * exactly this is the one that runs under ASan.
 *
 * THE REFUSALS:
 *
 *   arity            461, the tree's "you did not send enough", checked first because
 *                    a `BATCH` with no reference tag is not a batch.
 *   no type          461, on `+`. The grammar is `BATCH +reference-tag type`, and a
 *                    batch with no type is a batch the client cannot interpret.
 *   illegal ref      462 on both signs, with the reason in the text. `batch_ref_valid()`
 *                    has already refused the value, so nothing stored is touched.
 *   over-long ref    417. REFUSED, not truncated -- see batch.h.
 *   over-long type   417, same rule.
 *   one at a time    462 on a second `+`.
 *   unknown `-ref`   462, and the batch stays OPEN.
 *
 * WHY 462 FOR THE CASES WITH NO NUMERIC, honestly. RFC 2812 has no numeric for "you
 * already have one of those" -- 462 is `ERR_ALREADYREGISTRED`, ":Unauthorized command
 * (already registered)", which is about REGISTRATION. So this is a number borrowed for
 * an adjacent meaning, which §4.4.3 normally treats as the thing to avoid, and it is
 * used anyway for two reasons with the cost named:
 *
 *   - the alternative is SILENCE for a refused command, and §4.4's whole argument is
 *     that a client must never have to distinguish "refused" from "dropped";
 *   - the alternative to 462 is a NEW numeric, and §6 forbids inventing one for a
 *     case the RFC left open without an operator's decision.
 *
 * The text says what actually happened, so a client that reads it learns the truth
 * even though the number is borrowed. **IT IS NOT MIGRATED TO A `FAIL`**, for the same
 * reason 462 is not migrated in `handle_user()`: §4.4.3's rule moves a numeric only
 * where it answers more than one question ON THIS NODE, and here it would be answering
 * a question of ANOTHER SPECIFICATION's entirely.
 */
void handle_batch(server_t *s, conn_t *c, const message_t *m)
{
    const char *arg;

    if (m == NULL || c == NULL) {
        return;
    }
    if (m->nparams < 1) {
        (void)reply_refused(s, c, "BATCH", "NEED_MORE_PARAMS", "461", NULL, 0,
                            "Not enough parameters");
        printf("[observable] batch_refused: fd=%d reason=ARITY nparams=%d\n", c->fd,
               m->nparams);
        return;
    }
    arg = m->params[0];
    /* NO NESTING, AND IT IS CHECKED BEFORE ANYTHING ELSE. `client-batch`: "clients may
     * not send BATCH commands with a batch tag". A `BATCH` inside a batch would make
     * the batch structure a tree, and every piece of per-connection state on this node
     * is a FLAT single open batch -- so a nested open would overwrite
     * `conn_t::batch_ref` and every subsequent line would be tagged with the inner
     * reference while the client believed the outer one was still open.
     *
     * CHECKED FIRST because the check is about the LINE rather than about the verb's
     * arguments, and a malformed reference inside a nested BATCH should be reported as
     * the nesting it is rather than as a bad tag. */
    if (batch_line_tagged_inbound(m) != 0) {
        (void)reply_refused(s, c, "BATCH", NULL, "462", NULL, 0,
                            "BATCH may not be sent inside a batch");
        printf("[observable] batch_refused: fd=%d reason=NESTED open=%s\n", c->fd,
               (c->batch_ref[0] != '\0') ? c->batch_ref : "-");
        return;
    }
    if (arg[0] == '-') {
        /* THE '-' IS PART OF THE SYNTAX, NOT OF THE CLASS, so the class check applies
         * to what FOLLOWS it: the grammar is `BATCH -reference-tag`. `-+abc` is a
         * reference tag whose first character is a '-', and `-` alone is an empty
         * reference, refused below like any other. */
        const char *ref = arg + 1;

        if (batch_ref_valid(ref) == 0) {
            (void)reply_refused(s, c, "BATCH", NULL, "462", NULL, 0,
                                "No batch with that reference tag is open");
            printf("[observable] batch_refused: fd=%d reason=ILLEGAL_REF op=close\n",
                   c->fd);
            return;
        }
        /* AN EXACT, CASE-SENSITIVE MATCH, which is the specification's word ("The
         * reference tag ... MUST be case-sensitive") and the reason `strcmp()` and not
         * `strcasecmp()`: `BATCH -ABC` does not close a batch opened as `+abc`.
         *
         * AND IT IS AN `== 0` TEST, so a MISMATCH REFUSES AND LEAVES THE BATCH OPEN.
         * The alternative -- closing whatever is open regardless of the name -- would
         * make a client's own reference accounting wrong in the one case where it is
         * already wrong, and would silently discard the state that the remaining
         * `batch=` tags on this connection's lines depend on. */
        if (strcmp(ref, c->batch_ref) != 0) {
            (void)reply_refused(s, c, "BATCH", NULL, "462", NULL, 0,
                                "No batch with that reference tag is open");
            printf("[observable] batch_refused: fd=%d reason=UNKNOWN_REF op=close "
                   "wanted=%s open=%s\n",
                   c->fd, ref, (c->batch_ref[0] != '\0') ? c->batch_ref : "-");
            return;
        }
        c->batch_ref[0] = '\0';
        c->batch_type[0] = '\0';
        /* NO REPLY ON SUCCESS, and that is the shape of the verb rather than an
         * omission: `BATCH -ref` is a client's own bookkeeping, and the answer it needs
         * is the DISAPPEARANCE of `batch=` on the next line -- an absence rather than
         * a numeric. A `305`-style confirmation would be a line inside the batch about
         * the batch, which is self-referential and unspecified. */
        printf("[observable] batch_close: fd=%d ref=%s\n", c->fd, ref);
        return;
    }
    if (arg[0] == '+') {
        const char *ref = arg + 1;
        size_t tlen;

        if (batch_ref_valid(ref) == 0) {
            /* `INVALID_REFTAG <reference-tag>` IS `client-batch`'s OWN CODE, so it is
             * emitted as one -- and `reply_refused()` is what makes that per
             * destination: a client that negotiated `standard-replies` reads
             * `FAIL BATCH INVALID_REFTAG <ref>` and a client that did not reads the
             * legacy `417`, byte-identically to what it would have got otherwise.
             *
             * THE REFERENCE IS ECHOED AS SENT, untruncated and unescaped, which the
             * character rules make safe: it reached here having FAILED
             * `batch_ref_valid()`, so it may contain a byte that is not in the class,
             * and the failure could be a SP -- which `reply_refused()`'s `<context>`
             * would then have to escape. IT DOES NOT, and rather than depend on that
             * a context is not used at all: the code is in the message and the value
             * is on the observable line. That is a deliberate narrowing of the
             * specification's format -- the context parameter is "not intended for end
             * users but for developers", so a developer-grade refusal that omits an
             * unsafe parameter is the right trade, and the log carries it. */
            (void)reply_refused(s, c, "BATCH", "INVALID_REFTAG", "417", NULL, 0,
                                "Reference tag is not acceptable");
            {
                char shown[CONN_LOG_FIELD_MAX + 1u];
                const char *shown_ref = (ref[0] != '\0') ? ref : "";

                (void)conn_text_logsafe(shown, sizeof shown, shown_ref);
                printf("[observable] batch_refused: fd=%d reason=INVALID_REFTAG "
                       "ref=%s len=%zu ref_len=%zu ref_bad_bytes=%zu\n",
                       c->fd, shown, strlen(shown_ref), strlen(shown_ref),
                       conn_text_bad_count(shown_ref));
            }
            return;
        }
        /* A TYPE IS REQUIRED, and 461 rather than 462: this is a missing PARAMETER,
         * which is what 461 has always meant in this tree. */
        if (m->nparams < 2) {
            (void)reply_refused(s, c, "BATCH", "NEED_MORE_PARAMS", "461", NULL, 0,
                                "Not enough parameters");
            printf("[observable] batch_refused: fd=%d reason=NO_TYPE\n", c->fd);
            return;
        }
        /* THE TYPE IS BOUNDED AND REFUSED, NOT TRUNCATED, and the bound is 3.2's rule
         * applied to a value this node STORES. `batch/react` and
         * `draft/multiline-concat` are both well inside CONN_MAX_BATCH_TYPE. */
        tlen = strlen(m->params[1]);
        if (tlen > (size_t)CONN_MAX_BATCH_TYPE) {
            (void)reply_refused(s, c, "BATCH", NULL, "417", NULL, 0,
                                "Batch type is not acceptable");
            printf("[observable] batch_refused: fd=%d reason=TYPE_TOO_LONG "
                   "len=%zu max=%d\n",
                   c->fd, tlen, CONN_MAX_BATCH_TYPE);
            return;
        }
        /* `UNKNOWN_TYPE` IS NOT SENT, and this is where the argument belongs.
         *
         * `client-batch` defines the code as "the batch type is not recognized by the
         * server, all past and future messages in this batch will be ignored", and its
         * remedy is IGNORING the batch. This node does not ignore it: the framing is
         * TYPE-AGNOSTIC -- a batch here means "tag the lines this connection sends",
         * and that is true whatever the type is called -- so there is no type it
         * handles differently and therefore nothing to ignore.
         *
         * THE SAME DOCUMENT SAYS WHY THAT IS THE RIGHT SHAPE: it "does not introduce
         * any client-to-server batch type, but is designed as a framework for other
         * specifications". A framework with no types is exactly what this node has.
         *
         * THE COST, stated rather than discovered: a client that opens a
         * `draft/multiline` batch and is refused `UNKNOWN_TYPE` learns its type is
         * unsupported; a client that is ACCEPTED gets its lines delivered as ordinary
         * commands inside a batch, with no concatenation and no `max-bytes`/`max-lines`
         * accounting. For `draft/multiline` specifically those are the same
         * observable result -- the lines arrive, separately -- so the difference is
         * that the client is not told. It is told in the `batch_open:` observable line,
         * and `draft/multiline` is a phase this node has not reached.
         *
         * THE TYPE IS STORED ANYWAY, so the log can say which one was declared and so a
         * future type has somewhere to be read from. Nothing branches on it, and
         * CONN_MAX_BATCH_TYPE says so at the constant. */
        /* ONE AT A TIME, and the cost is named rather than treated as free: the
         * specification's own client-side model is a flat one -- open, send, close --
         * and `draft/multiline`, the reason this exists, opens ONE batch per message
         * group. A client wanting two concurrent groups is out of scope and is TOLD SO.
         *
         * THE REFUSAL IS NOT `BATCH -ref` UNDERNEATH. Re-opening is not a transaction
         * this node performs: the client's own reference accounting would be the thing
         * that broke, and silently closing a batch it believes is open would make every
         * subsequent line's `batch=` tag wrong in a way the client cannot detect. */
        if (c->batch_ref[0] != '\0') {
            (void)reply_refused(s, c, "BATCH", NULL, "462", NULL, 0,
                                "You already have a batch open");
            printf("[observable] batch_refused: fd=%d reason=ALREADY_OPEN open=%s\n",
                   c->fd, c->batch_ref);
            return;
        }
        /* THE TWO COPIES. See the header: `m->params` is the parser's heap and the
         * connection is not. */
        memcpy(c->batch_ref, ref, strlen(ref) + 1u);
        memcpy(c->batch_type, m->params[1], tlen + 1u);
        /* A ONE-SHOT NAMED IN THE SAME LINE IS DROPPED, because `+ref` opening the
         * batch means every line is already inside it and a second reference to the
         * same batch would be a no-op with a stale lifetime. */
        c->batch_once[0] = '\0';
        printf("[observable] batch_open: fd=%d ref=%s type=%s\n", c->fd, c->batch_ref,
               c->batch_type);
        return;
    }
    /* NEITHER SIGN. 462 rather than 421: the verb EXISTS on this node, and 421 would
     * tell a client "this server has never heard of BATCH", which is a lie about a
     * verb the dispatch table has a row for. The reference is malformed and the text
     * says so. */
    (void)reply_refused(s, c, "BATCH", NULL, "462", NULL, 0,
                        "Batch reference must begin with '+' or '-'");
    /* Rule 1, and this is the LOWEST-PRIVILEGE instance of the class in the tree:
     * `BATCH` is `pre_reg`, so this line is reachable from a socket that has never
     * registered and has never joined anything. One line on a socket was enough to
     * put a control byte in an operator's terminal, and `%c` is why -- the format
     * reads as harmless in a list of printf sites, and a byte walked into it by the
     * caller is invisible there.
     *
     * `conn_text_logsafe()` WITHHOLDS rather than filters: `first=-` says there was a
     * value and it was not safe to print, and the three measurements beside it say
     * which. The hex byte is the one that matters, because `first_len=1` alone does
     * not distinguish ESC from BEL from a NUL and an operator reading this line wants
     * to know which control byte a client sent at it.
     *
     * COST: one pass over one byte, on a path that runs once per malformed reference. */
    {
        char raw[2];
        char shown[CONN_LOG_FIELD_MAX + 1u];

        raw[0] = arg[0];
        raw[1] = '\0';
        (void)conn_text_logsafe(shown, sizeof shown, raw);
        printf("[observable] batch_refused: fd=%d reason=NO_SIGN first=%s first_byte=0x%02x "
               "first_len=%zu first_bad_bytes=%zu\n",
               c->fd, shown, (unsigned char)arg[0], strlen(raw),
               conn_text_bad_count(raw));
    }
}
