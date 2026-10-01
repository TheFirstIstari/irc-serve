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
    size_t len;

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
