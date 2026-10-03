/* label.c -- see label.h. `labeled-response`: copy the client's label, put it on exactly
 * one logical message, group a multi-line response in a batch, and answer `ACK` when a
 * labelled command produced nothing.
 *
 * The argument for each decision lives in label.h and in the specification; what is here
 * is the code and the two boundaries that are about THIS file.
 */
#include "core/label.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "core/cap.h"
#include "ircv3_tags.h"
#include "core/reply.h"

/* ---------------------------------------------------------------------------
 * The batch reference this node mints
 * ---------------------------------------------------------------------------
 * IT IS PER CONNECTION, and that is a correctness claim rather than an economy: the
 * client is the only party that sees these references, so two connections minting the
 * same value cannot collide from anybody's point of view -- while two batches on ONE
 * connection must not collide, and a per-connection counter cannot.
 *
 * THE PREFIX IS `lr`, which is two characters chosen so a client reading a log can tell
 * a `labeled-response` batch from one it opened itself, and so a value minted here can
 * never be confused with a `draft/multiline` reference the client chose. The digits are
 * ZERO-PADDED to a fixed width for a second reason: a reference tag is an OPAQUE
 * identifier, so its only requirement is that it differ from every other one on the same
 * connection, and a fixed width makes that true by construction rather than by counting.
 *
 * IT IS BUILT WITH `snprintf` INTO A FIXED BUFFER, not allocated, and CONN_MAX_LABEL
 * bounds it: "lr" + 10 digits is 12 bytes against a 64-byte bound, so the cast to
 * `size_t` is safe and the `cap` argument is the one that keeps it that way if the bound
 * is ever lowered.
 */
#define LABEL_BATCH_PREFIX "lr"

static void mint_batch_ref(conn_t *c, char *out, size_t cap)
{
    (void)snprintf(out, cap, "%s%010lu", LABEL_BATCH_PREFIX,
                   (unsigned long)(++c->label_seq));
}

/* ---------------------------------------------------------------------------
 * The inbound label
 * ---------------------------------------------------------------------------
 * FINDING IT IS A SCAN, and for the same reason batch.c's is: the value is in
 * `m->tags`, which the parser has already validated as a whole block, and the key is a
 * literal (`label`, no sigil) so `message_tag_get()` would work too. The scan is here
 * rather than delegating for one reason that matters: **the value is taken VERBATIM, not
 * unescaped**, and that is not an oversight -- see below.
 *
 * THE VALUE IS TAKEN UNESCAPED ON PURPOSE. A tag value is escaped on the wire, so a
 * client that wanted a space in its label sends `label=a\sb`, and the value it chose is
 * `a b`. The label is COPIED into `conn_t::label` and re-emitted through
 * `message_build()`, which escapes it again on the way out -- so taking it raw would
 * double-escape. It is therefore UNESCAPED here, into a caller buffer, and the tag
 * builder re-escapes it. That is the same round trip `ircv3_tags.c` exists to make
 * correct, and it is why this function does not hand `m->tags`'s bytes to anybody.
 *
 * THE BOUND IS THE SPECIFICATION'S 64 BYTES and it is checked BEFORE the copy, not
 * after: a label longer than that is IGNORED, not truncated, because 3.2 forbids
 * delivering a shortened value and a truncated label would be a value the client did not
 * choose -- silently correlating a response against the wrong request.
 */
void label_begin_command(conn_t *c, const message_t *m)
{
    const char *p;
    const char *val = NULL;
    size_t len = 0;
    int found = 0;

    /* DISARM FIRST, so a command with no label cannot inherit one. The state is
     * per-command and nothing about it survives the tail's `label_finish_command()`;
     * clearing it here as well makes the function's effect independent of the caller's
     * discipline, which is the property that keeps an early return in the tail from
     * stranding a live label. */
    c->label_live = 0;
    c->label[0] = '\0';
    c->label_batch[0] = '\0';
    c->label_batch_open = 0;
    c->label_self = 0;
    if (m == NULL || m->tags == NULL) {
        return;
    }
    p = m->tags;
    while (*p != '\0' && found == 0) {
        const char *key = p;
        size_t klen;

        while (*p != '\0' && *p != ';' && *p != '=') {
            p++;
        }
        klen = (size_t)(p - key);
        if (*p == '=') {
            const char *vstart = p + 1;

            p++;
            while (*p != '\0' && *p != ';') {
                p++;
            }
            /* COMPARED CASE-INSENSITIVELY: IRCv3 tag KEYS are case-insensitive, and a
             * client that wrote `@Label=` has written `label`. */
            if (klen == 5u && strncasecmp(key, "label", 5u) == 0) {
                val = vstart;
                len = (size_t)(p - vstart);
                found = 1;
            }
        } else if (klen == 5u && strncasecmp(key, "label", 5u) == 0) {
            /* A VALUELESS `label` IS NOT A LABEL. The specification says the tag "has a
             * REQUIRED value", so a client that sent one has sent something this node
             * cannot echo, and the honest answer is to treat it as absent rather than to
             * echo an empty one -- which would put `label=` on the wire, a value the
             * client never chose and cannot correlate against. */
            printf("[observable] label_ignored: fd=%d reason=NO_VALUE\n", c->fd);
            found = 1;
        }
        if (*p == ';') {
            p++;
        }
    }
    if (found == 0 || val == NULL) {
        return;
    }
    if (len == 0u) {
        printf("[observable] label_ignored: fd=%d reason=EMPTY\n", c->fd);
        return;
    }
    if (len > (size_t)CONN_MAX_LABEL) {
        printf("[observable] label_ignored: fd=%d reason=TOO_LONG len=%zu max=%d\n",
               c->fd, len, CONN_MAX_LABEL);
        return;
    }
    /* THE UNESCAPE. `ircv3_unescape_value()` never grows a value, so `len` bytes plus a
     * NUL always fit in the connection's own field -- and it returns -1 rather than
     * truncating, so the -1 arm below is reachable only if that property ever stops
     * holding, and it is handled rather than ignored. */
    if (ircv3_unescape_value(val, len, c->label, sizeof c->label) != 0) {
        c->label[0] = '\0';
        printf("[observable] label_ignored: fd=%d reason=UNESCAPE_FAILED len=%zu\n",
               c->fd, len);
        return;
    }
    c->label_live = 1;
    printf("[observable] label: fd=%d len=%zu\n", c->fd, strlen(c->label));
}

int label_is_grouping_verb(const char *code)
{
    return (code != NULL && strcmp(code, "BATCH") == 0) ? 1 : 0;
}

/* ---------------------------------------------------------------------------
 * The reply hook
 * ---------------------------------------------------------------------------
 * "IS THIS THE CLIENT'S OWN MESSAGE?" IS A FIELD AND NOT A COMPARISON, and the
 * distinction is the whole of this specification's one exception.
 *
 * The specification says "When a client sends a message to itself, the server MUST NOT
 * include the label tag". **A message to itself** means a message ADDRESSED to itself --
 * `PRIVMSG <own nick>`. It does NOT mean a message the client sent to somebody else: this
 * node hands a sender its own channel message back when it negotiated `echo-message`
 * (Phase 10.7), and that echo's SOURCE is the sending client, so a rule keyed on the
 * source withholds the label from every echoed message on the node.
 *
 * The first version of this function compared the line's prefix against the destination's
 * own hostmask, which is a SOURCE test, and `test_labeled_response.c` case 7 caught it as
 * a labelled `PRIVMSG #chan` producing an unlabelled echo followed by an `ACK`. The
 * question is now `conn_t::label_self`, set by `msg_verbs.c` where the resolved target and
 * the sender are both in scope -- `emit_built_ex()` has the line and the destination and
 * nothing else, so a comparison here could never have been about the target.
 *
 * `label_begin_command()` CLEARS IT, so it is a property of the command in flight and not
 * of the connection: a command that is not a message at all inherits nothing.
 */

int label_line_tag(server_t *s, conn_t *c, const char *code, const char *prefix,
                   char *out, size_t cap)
{
    int n;

    /* `prefix` IS TAKEN AND NOT USED. It is still a parameter rather than removed: it is
     * where a future rule about WHICH lines may carry a label at all belongs, and
     * dropping it from three call sites to save one cast would be the more expensive
     * change. The cast says so rather than leaving a reader to wonder. */
    (void)prefix;

    if (c == NULL || out == NULL || cap == 0u) {
        return 0;
    }
    out[0] = '\0';
    if (c->label_live == 0) {
        return 0;
    }
    /* A GROUPING VERB IS NEVER TAGGED BY THIS FUNCTION, and the check is here rather
     * than only at the call site because the `BATCH +` line this module emits for the
     * first response line is emitted THROUGH `emit_built_ex()`, so it would otherwise be
     * tagged `batch=<its own ref>` and a client would see the start of a batch
     * announcing itself as inside that batch. */
    if (label_is_grouping_verb(code) != 0) {
        return 0;
    }
    if (c->label_self != 0) {
        return 0;
    }
    if (c->label_batch_open == 0) {
        /* THE FIRST LINE. Two things happen here and the order is the argument.
         *
         * The grouping batch is minted and STARTED -- which means a `BATCH +<ref>
         * labeled-response` line is queued ahead of this one, carrying `label=<value>`
         * -- and only then is `batch=<ref>` returned for the line itself.
         *
         * THE BATCH IS ONLY STARTED FOR A CLIENT THAT NEGOTIATED THE CAPABILITY. The
         * specification says "Clients requesting this capability indicate that they are
         * capable of handling the message tag, batch type, and ACK response", and a
         * `BATCH` command word on the wire to a client that never asked for this
         * capability is the same mistake §4.4.3 refuses for `FAIL`: it is a command word
         * no such client was ever told to expect. A client that negotiated nothing gets
         * the LABEL and no batch, which satisfies "the tag in exactly one logical
         * message" with the single message being the whole response.
         *
         * `label_batch_open` IS SET BEFORE THE EMISSION, so the recursive
         * `emit_built_ex()` the `BATCH +` line causes takes the other arm. */
        if (cap_labeled_response_enabled(c) != 0) {
            mint_batch_ref(c, c->label_batch, sizeof c->label_batch);
            {
                const char *open[2];
                char tags[LABEL_TAG_MAX];
                /* THE '+' AND THE '-' ARE PART OF THE SYNTAX, NOT OF THE REFERENCE, so
                 * they live in a local two-line buffer rather than in `label_batch`. The
                 * reference in the field is the BARE one, which is what `@batch=` carries
                 * and what the specification means by "the batch's reference tag"; a
                 * stored `+lr…` would put a sign into every tag on every later line. */
                char signed_ref[2u + (size_t)CONN_MAX_LABEL];

                (void)snprintf(signed_ref, sizeof signed_ref, "+%s", c->label_batch);
                open[0] = signed_ref;
                open[1] = "labeled-response";
                /* THE `label=` TAG GOES ON THE BATCH START AND NOWHERE ELSE, which is
                 * the specification's own shape -- "The start of the batch MUST be
                 * tagged with the label tag" -- and the tag block is rendered by
                 * `message_build()`'s escaping, so the value is safe whatever bytes the
                 * client chose. `CONN_MAX_LABEL + 16` is "label=" (6) plus the widest
                 * value plus the NUL, and it is derived rather than picked. */
                (void)snprintf(tags, sizeof tags, "label=%s", c->label);
                c->label_batch_open = 1;
                (void)send_line_tagged(s, c, NULL, "BATCH", open, 2, tags);
                /* THE FIRST RESPONSE LINE IS INSIDE THE BATCH AND THEREFORE CARRIES
                 * THE REFERENCE, not the label. That is the specification's own example
                 * exactly -- `@label=…` on the `BATCH +` and `@batch=…` on the `311` --
                 * and getting it the other way round puts the label on two messages,
                 * which is the one thing "exactly one logical message" forbids. */
                n = snprintf(out, cap, "batch=%s", c->label_batch);
                return (n > 0 && (size_t)n < cap) ? 1 : 0;
            }
        }
        /* NO CAPABILITY, SO NO GROUPING: the label goes on the single response message
         * itself, which is the whole logical response. */
        n = snprintf(out, cap, "label=%s", c->label);
        return (n > 0 && (size_t)n < cap) ? 1 : 0;
    }
    /* EVERY LATER LINE, INSIDE THE BATCH. The label is NOT repeated -- "exactly one
     * logical message" -- and the reference is what ties the rest of the response
     * together. */
    n = snprintf(out, cap, "batch=%s", c->label_batch);
    return (n > 0 && (size_t)n < cap) ? 1 : 0;
}

/* ---------------------------------------------------------------------------
 * The tail
 * ---------------------------------------------------------------------------
 * TWO EXITS AND NOTHING ELSE, and which one applies is the whole of the `ACK`
 * requirement:
 *
 *   a batch was opened   close it. `:srv BATCH -<ref>`, untagged, because the
 *                        specification's own example closes with an untagged line and a
 *                        close inside the batch it is closing is self-referential.
 *   nothing was emitted  `ACK`, which is what "Servers MUST respond with a labeled ACK
 *                        message when a client sends a labeled command that normally
 *                        produces no response" means operationally: on this node the
 *                        distinction is not observable from outside, so "produced no
 *                        response" is the testable form of "normally produces no
 *                        response". A client that gets nothing at all cannot tell
 *                        success from a dropped line, which is the failure mode 4.4's
 *                        numerics exist to prevent and the one `ACK` exists to remove.
 *
 * `ACK` IS GATED ON THE CAPABILITY, and it is the same argument as for `BATCH +` above:
 * a command word on the wire to a client that was never told to expect it. A client that
 * sent a `label=` without negotiating gets the label on its responses and **no `ACK`**,
 * and that asymmetry is deliberate -- the label is what the tag is for and it costs the
 * client nothing it asked for, while `ACK` is a new verb.
 */
void label_finish_command(server_t *s, conn_t *c)
{
    char saved[CONN_MAX_LABEL + 1];
    char signed_ref[2u + (size_t)CONN_MAX_LABEL];
    char tags[LABEL_TAG_MAX];
    int opened;

    if (c == NULL || c->label_live == 0) {
        return;
    }
    opened = c->label_batch_open;
    /* THE LABEL AND THE REFERENCE ARE COPIED OUT BEFORE ANYTHING IS EMITTED, because
     * both of the lines below go through `emit_built_ex()`, which asks
     * `label_line_tag()` -- and if the state were still live the ACK would trigger the
     * very batching this function exists to avoid, producing a `BATCH +` in front of an
     * `ACK` inside a batch that nothing ever closed. The first version of this function
     * emitted first and cleared afterwards and did exactly that; the two lines below it
     * carried `@batch=<its own ref>;label=<value>`, which is a tag block no client can
     * make sense of. */
    memcpy(saved, c->label, sizeof saved);
    if (opened != 0) {
        (void)snprintf(signed_ref, sizeof signed_ref, "-%s", c->label_batch);
    }
    (void)snprintf(tags, sizeof tags, "label=%s", saved);

    /* DISARM, AND THE ORDER MATTERS: before the emission above rather than after it, so
     * that the recursive `emit_built_ex()` these calls cause sees a connection that owes
     * nothing. */
    c->label_live = 0;
    c->label[0] = '\0';
    c->label_batch[0] = '\0';
    c->label_batch_open = 0;

    if (opened != 0) {
        const char *close[1];

        close[0] = signed_ref;
        /* `send_line_tagged()` with a NULL block, which is the one way to say "no tags"
         * here: an EMPTY string is refused by that function as `empty_tags`, because an
         * empty block is not one this node can have produced. */
        (void)send_line_tagged(s, c, NULL, "BATCH", close, 1, NULL);
        printf("[observable] label: fd=%d closed=1\n", c->fd);
        return;
    }
    if (cap_labeled_response_enabled(c) != 0) {
        const char *none[1];

        none[0] = NULL;
        /* `:srv ACK` -- no parameters at all, which is the specification's shape
         * (`:irc.example.com ACK`), and `nparams = 0` renders it with no trailing colon
         * rather than `:`. */
        (void)send_line_tagged(s, c, NULL, "ACK", none, 0, tags);
        printf("[observable] label: fd=%d ack=1 len=%zu\n", c->fd, strlen(saved));
        return;
    }
    /* A CLIENT THAT NEGOTIATED NOTHING GETS NOTHING, and the observable says so rather
     * than leaving it to be inferred from the absence of a line: it labelled a command,
     * nothing came back, and that is correct -- there is no numeric that means "your
     * label was not acknowledged" and `ACK` is a verb it did not ask for. */
    printf("[observable] label: fd=%d reason=NO_CAPABILITY_FOR_ACK\n", c->fd);
}
