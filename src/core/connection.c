/* connection.c -- conn_t buffers and RFC 1459 2.3 line framing (3.3).
 *
 * PHASE 12: this file no longer calls recv() or send(). Both went to
 * core/transport.h -- see transport.h for the contract and for why there are
 * three call sites and not the twelve a grep suggests. What stayed here is the
 * part that is about the CONNECTION (framing, the bounded write queue, the
 * lifecycle) rather than about the bytes, and conn_pump()'s STARTTLS ordering
 * arm is the one piece of transport policy that has to live here, for the
 * reason its own comment gives.
 */
#include "core/connection.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>

#include "core/transport.h"

/* Grow `*buf` to at least `need` bytes, doubling from the current capacity and
 * clamping to `limit` so a capped buffer cannot be grown past its bound. Sets
 * *cap to the new capacity. Returns 0 on success, -1 if the request is
 * impossible or the allocation fails (leaving the old buffer intact, so a
 * caller that fails here still has a usable conn). */
static int buf_grow(char **buf, size_t *cap, size_t need, size_t limit)
{
    size_t want = (*cap == 0) ? 512u : *cap;
    char *next;

    if (need > limit) {
        return -1;
    }
    while (want < need) {
        if (want > limit / 2u) {
            want = limit;
            break;
        }
        want *= 2u;
    }

    next = (char *)realloc(*buf, want);
    if (next == NULL) {
        return -1;
    }
    *buf = next;
    *cap = want;
    return 0;
}

conn_t *conn_new(int fd, int kind)
{
    conn_t *c = (conn_t *)calloc(1, sizeof *c);

    if (c == NULL) {
        return NULL;
    }
    c->fd = fd;
    c->kind = kind;
    c->state = CONN_REG_PASS;
    /* Phase 12: the READINESS INTENT a plaintext connection starts with, and
     * the value that makes the loop's poll set for this connection byte-for-byte
     * what it was before the intent existed. See the block in connection.h.
     *
     * want_read is 1 unconditionally on a plaintext connection, because a
     * plaintext socket always wants to be read; want_write is 0 because there
     * is nothing queued, and conn_queue() raises it the first time that stops
     * being true. Nothing here talks to a transport: conn_new() installs the
     * plaintext ops below and a TLS connection's own ops publish their intent
     * the moment they exist. */
    c->want_read = 1;
    c->want_write = 0;
    /* ...and the transport, which is the plaintext one because a brand-new
     * conn_t has no TLS on it and the only two ways to get any are
     * transport_starttls() (a STARTTLS, or an implicit-TLS listener's accept)
     * and the peer-link dial. This call is what makes "every connection has a
     * transport from the instant it exists" true rather than something each
     * construction site has to remember -- see transport.h. */
    transport_init_plaintext(c);
    /* The two 317 RPL_WHOISIDLE timestamps, stamped where the connection comes
     * into existence rather than where they are asked for. signon_at is the
     * answer to "when did this user connect", which is a fact about accept and
     * is therefore true from this instant; last_active starts equal to it so an
     * idle time measured before the client has said anything is zero rather
     * than whatever the epoch happened to be.
     *
     * This is a wall-clock read, which 3.4 otherwise forbids in handlers ("the
     * poll tick drives time"). The rule is about TIME-OUT logic -- handshake
     * deadlines, link liveness, LRU eviction -- which must be immune to a clock
     * jump. 317 is the opposite case: its <signon time> is a calendar time the
     * client is meant to compare against its own clock, so no monotonic
     * substitute would be the right value. It is read once per connection,
     * never per tick, and commands.c's 003 already established the precedent
     * and the reasoning for exactly one such read on the reply path. */
    c->signon_at = time(NULL);
    c->last_active = c->signon_at;
    return c;
}

void conn_free(conn_t *c)
{
    if (c == NULL) {
        return;
    }
    /* Phase 12: the transport is released HERE, and this is the only place an
     * SSL* is freed on the connection path -- conn_free() is what
     * server_close_conn(), server_dial_progress()'s two failure arms and
     * server_shutdown()'s walk all end in, so "every TLS connection frees its
     * SSL" is one call in one function rather than four call sites somebody has
     * to keep in step.
     *
     * It runs BEFORE the buffers because the drain in
     * fed_send_shutdown() has already run by then and nothing below it needs the
     * transport; and it runs whether or not the connection was ever TLS, because
     * the plaintext close is a no-op and branching on that here would be a
     * second place that has to know what the transport is.
     *
     * NOT CLOSING THE DESCRIPTOR: 3.4 makes the reaper the single close site and
     * this function does not close the fd, so the TLS close must not either.
     * OpenSSL is told about the teardown with SSL_shutdown() and then dropped;
     * the socket is closed by close() a line later in server_close_conn(). */
    transport_close(c);
    free(c->rbuf);
    free(c->wbuf);
    free(c->peer_name);
    /* The elements are owned by the channel registry (2.2: a chan_t outlives
     * any single member), so only the index array belongs to the conn. */
    free(c->chans);
    free(c);
}

int conn_fill(conn_t *c)
{
    for (;;) {
        size_t room;
        ssize_t n;

        if (c->rlen == c->rcap) {
            if (c->rcap >= CONN_RBUF_MAX) {
                return 0; /* capped: framing decides whether this is legal */
            }
            if (buf_grow(&c->rbuf, &c->rcap, c->rlen + 1u, CONN_RBUF_MAX) != 0) {
                return -1;
            }
        }

        room = c->rcap - c->rlen;
        /* Phase 12: the read goes through the transport, which is where the
         * recv() and the errno policy moved to. What is left here is the part
         * that is about the CONNECTION rather than about the bytes: appending,
         * the idle stamp, and the three outcomes the loop's EOF and error arms
         * already distinguish. The buffer is never full at this point -- the
         * block above guarantees room -- which matters for TLS: a transport with
         * decrypted bytes already buffered returns them without touching the
         * descriptor, and it may only do that because the caller always has
         * somewhere to put them. */
        n = transport_recv(c, c->rbuf + c->rlen, room);
        if (n > 0) {
            c->rlen += (size_t)n;
            /* Bytes arrived, so the connection is not idle. This is the only
             * place in the node that observes the connection DOING something,
             * which is what makes it the right place to stamp 317's <idle>
             * from: stamping it in a command handler would report a client as
             * idle while it was mid-burst, and stamping it nowhere would make
             * the number a constant. */
            c->last_active = time(NULL);
            continue;
        }
        if (n == 0) {
            return CONN_FILL_EOF; /* the peer closed its half */
        }
        if (n == TRANSPORT_RETRY) {
            return 0; /* drained to EAGAIN, or the transport wants something else */
        }
        return -1;
    }
}

int conn_next_line(conn_t *c, char *dst, size_t dstcap, size_t *len)
{
    const char *nl;
    size_t used;
    size_t rest;

    if (dst == NULL || len == NULL || dstcap == 0) {
        return -1;
    }
    nl = (const char *)memchr(c->rbuf, '\n', c->rlen);
    if (nl == NULL) {
        /* No terminator in hand. Once the buffer is at the line cap the line
         * can never become legal, so this is reported now rather than after
         * the peer stops sending. */
        return (c->rlen >= CONN_RBUF_MAX) ? -1 : 0;
    }

    used = (size_t)(nl - c->rbuf) + 1u; /* the LF, and the CR before it */
    rest = c->rlen - used;
    if (used > dstcap) {
        return -1;
    }

    /* Copy BEFORE compacting. The line is the front of the buffer and the
     * remainder has to slide down over it to reclaim the space, so the order
     * of these two operations is load-bearing. */
    memcpy(dst, c->rbuf, used);
    *len = used;

    if (rest > 0) {
        memmove(c->rbuf, c->rbuf + used, rest);
    }
    c->rlen = rest;
    return 1;
}

int conn_queue(conn_t *c, const char *data, size_t len)
{
    size_t pending = c->wlen - c->woff;

    if (len == 0) {
        return 0;
    }
    /* The cap is on the unsent tail, and it is checked BEFORE the buffer is
     * grown, so an over-cap append is refused without allocating anything. */
    if (len > CONN_WQ_MAX - pending) {
        return -1;
    }

    /* Reclaim the already-sent head before growing, so a connection that has
     * been writing for hours reuses one allocation instead of ratcheting.
     *
     * The third condition matters as much as the first two. The cap is on the
     * UNSENT tail, so an allocation that has ratcheted close to the cap can
     * refuse a legitimate append -- one that is well inside the bound -- simply
     * because growing to fit would exceed the allocation limit. When woff is
     * small that leaves the caller with a refusal that means "no room" while
     * the counter says "over the cap", which is a lie the diagnostics cannot
     * tell apart. Compacting whenever the growth would not fit removes that.
     *
     * With woff == 0 the allocation is the tail, so the cap check above already
     * guarantees the growth fits and this cannot trigger. */
    if (c->woff > 0 && (c->woff == c->wlen || c->woff >= CONN_WQ_COMPACT ||
                        c->wlen + len > CONN_WQ_MAX)) {
        if (c->woff == c->wlen) {
            c->wlen = 0;
            c->woff = 0;
        } else {
            memmove(c->wbuf, c->wbuf + c->woff, c->wlen - c->woff);
            c->wlen -= c->woff;
            c->woff = 0;
        }
    }

    if (c->wlen + len > c->wcap) {
        if (buf_grow(&c->wbuf, &c->wcap, c->wlen + len, CONN_WQ_MAX) != 0) {
            return -1;
        }
    }
    memcpy(c->wbuf + c->wlen, data, len);
    c->wlen += len;
    /* Phase 12: the queue grew, so poll() must be asked for POLLOUT. This is the
     * ONE place outside a transport that may set the intent, and the reason is
     * in connection.h: a transport's last publish predates these bytes, so it
     * cannot know they exist. See conn_queue()'s comment. */
    c->want_write = 1;
    return 0;
}

void conn_want(conn_t *c, int read, int write)
{
    if (c == NULL) {
        return;
    }
    c->want_read = read ? 1 : 0;
    c->want_write = write ? 1 : 0;
}

int conn_pump(conn_t *c)
{
    for (;;) {
        size_t pending = c->wlen - c->woff;

        /* Phase 12: the EMPTY pass. A TLS handshake writes before this node has
         * any application bytes to send, so the transport gets one unconditional
         * call with a zero-length buffer even when there is nothing queued; the
         * plaintext transport answers it without touching the descriptor. This
         * is reached only after the queue has drained, which is why the ordinary
         * path below it is unchanged. */
        if (pending == 0u) {
            (void)transport_send(c, NULL, 0u);
            break;
        }
        /* MSG_NOSIGNAL for the plaintext case is the transport's business and
         * not this file's -- a peer that has already gone away must surface as
         * EPIPE, never as a process-killing SIGPIPE, whichever transport is
         * carrying the bytes. */
        {
            ssize_t n = transport_send(c, c->wbuf + c->woff, pending);

            if (n > 0) {
                c->woff += (size_t)n;
                continue;
            }
            if (n == TRANSPORT_RETRY) {
                break; /* partial write: the rest is drained on a later tick */
            }
            return -1;
        }
    }

    if (c->woff == c->wlen) {
        c->wlen = 0;
        c->woff = 0;
    }
    /* Phase 12: a STARTTLS whose 670 has now been fully written may start its
     * handshake. Doing it HERE rather than in the handler is the whole of the
     * ordering: the confirmation has to reach the client IN THE CLEAR, and a
     * handler that began the handshake at once would have OpenSSL's first
     * flight racing the 670 down the same socket -- a client that received a
     * ServerHello before the line that authorised it would have no way to know
     * the ordering was intended. See transport_starttls(). */
    if (c->starttls_pending && c->woff == c->wlen) {
        c->starttls_pending = 0;
        if (transport_starttls(c, 1) != 0) {
            printf("[observable] starttls_failed: fd=%d reason=HANDSHAKE_START\n",
                   c->fd);
            return -1;
        }
    }
    return 0;
}

size_t conn_write_pending(const conn_t *c)
{
    return c->wlen - c->woff;
}

void conn_mark_closing(conn_t *c)
{
    c->state = CONN_CLOSING;
}

size_t conn_hostmask(const conn_t *c, char *out, size_t cap)
{
    int n;

    if (c == NULL || out == NULL || cap == 0) {
        return 0;
    }
    /* snprintf rather than strcpy/strcat: a hostmask is three
     * client-influenced fields concatenated, and a client that filled nick, user
     * and host to their bounds would overflow a buffer sized for any two of
     * them. snprintf reports the truncation instead of causing it, and returning
     * 0 makes the caller treat the whole line as unrenderable -- 3.2's rule
     * about never delivering a silently shortened field, applied to the
     * prefix. */
    n = snprintf(out, cap, "%s!%s@%s", c->nick, c->user, c->host);
    if (n < 0 || (size_t)n >= cap) {
        out[0] = '\0';
        return 0;
    }
    return (size_t)n;
}

/* ---------------------------------------------------------------------------
 * THE REALNAME VALIDATOR, and why it is ONE function for two callers
 * ---------------------------------------------------------------------------
 * `conn_t::realname` is written from two places and read from three: `USER`'s
 * fourth parameter (handle_user()), IRCv3's `SETNAME` (handle_setname()), and
 * rendered by `extended-join`'s trailing parameter, by `352`'s <realname> and by
 * 4.3's SBURSTN. A field with two writers and three readers needs the writers to
 * agree, and the alternative -- each caller deciding for itself -- is a second
 * opinion about what may be stored, which is how the two come to disagree.
 *
 * SO: ONE predicate, called by both. That is what makes "SETNAME is not a looser
 * path than USER" a property of the code rather than a claim about it -- a
 * reviewer can read one function and know both writers ran it.
 *
 * ---------------------------------------------------------------------------
 * THE TWO REFUSALS, AND WHY EACH EXISTS
 * ---------------------------------------------------------------------------
 *   TOO_LONG     3.2's "never deliver a silently shortened parameter". A truncated
 *                realname is one the user did not write, and this node then shows it
 *                to every member of every channel that person is on. 005 advertises
 *                the bound as NAMELEN (Phase 10.4), so it is also the number a client
 *                sizes its own buffer from; a server that stores a fifth of it is the
 *                server that broke the promise.
 *
 *   BAD_BYTE     A realname reaches the node's own LOG, with no escaping between
 *                the socket and a printf("%s"). message_parse_n() refuses CR, LF
 *                and NUL already, so the three that matter most cannot arrive; what
 *                CAN arrive is every other C0 control and DEL. 0x07 rings the
 *                recipient's terminal bell, and ESC followed by `[` is a CSI
 *                sequence any terminal will execute -- which is a realname that
 *                rewrites the operator's screen, from a channel member, into a log
 *                that other tooling also reads.
 *
 *                It was once "the one client-supplied free-text field with no
 *                escaping between the socket and a printf(\"%s\")", and that was
 *                true until #121 found the two that were not -- USER's
 *                <servername> and AWAY's text -- and then found the topic as well.
 *                The claim is corrected here rather than left: it is exactly the
 *                kind of sentence that makes the next reader believe the set is
 *                closed.
 *
 *                The test is `ch <= 0x1f || ch == 0x7f`, and it is the SAME rule
 *                `chan_name_valid()` already applies to a channel name (channel.c),
 *                for the same reason. TAB is inside that range and is therefore
 *                refused too; a realname is a GECOS field and a TAB in one is a
 *                rendering accident rather than a name, and no current client sends
 *                one. That is the cost, and it is named rather than assumed.
 *
 * NULL IS OK: an empty realname is a legal state (chan_verbs.c's extended-join
 * comment says so, and renders it as a bare `:`), and a client that clears its own
 * realname must be able to say so.
 *
 * THE BYTE TEST IS NOT WRITTEN HERE, and THAT IS THE WHOLE FIX.
 *
 * It used to be `conn_text_bad_count(name) != 0`, which asks `conn_byte_is_bad()`
 * and therefore counts C0 and DEL ONLY. The strip the tree applies to a STORED
 * field -- `conn_text_strip()`, i.e. this same walk in strip mode -- also removes a
 * RAW C1 (`0x80`-`0x9F` with nothing expecting a continuation) and the ENCODED C1
 * pair `0xC2 0x80`-`0xC2 0x9F`, because on an 8-bit terminal `0x9B` IS CSI. So the
 * check accepted realnames the strip would have rewritten, which is the divergence
 * connection.c's own header warns about: "two functions answering 'which bytes are
 * dangerous' is how they come to disagree".
 *
 * IT WAS LATENT rather than live, and the reason is worth stating because it is the
 * only reason this survived: `311` renders the realname through
 * `emit_numeric_ex()`, which runs `conn_text_strip_wire()`, so the byte was removed
 * before it could reach a third party. What was left was a stored value this node
 * had accepted and would then quietly mangle -- `Ma<0x9F>llory` shown to every
 * member of every channel as `Mallory`-with-a-hole, and a realname that no longer
 * matched the one the user typed, on a field whose whole policy is "refuse rather
 * than rewrite" (3.2: never deliver a silently altered parameter).
 *
 * SO IT ASKS `conn_text_display_check()`, which is THE SAME WALK in check mode --
 * the walk `valid_nick()` uses for `conn_t::nick`, which is the other stored field
 * rendered into every line its owner sends. One definition, asked twice.
 *
 * AND IT IS NOW STRICTER THAN THE STRIP IN ONE RESPECT, which is deliberate and is
 * the walk's own documented difference: check mode also faults INVALID UTF-8 -- an
 * overlong `0xC0`/`0xC1`, a surrogate half, a lead byte outside UTF-8, a sequence
 * that stops early -- where a stripper passes them through. `text_step()` argues
 * that split at length: "A stripper may pass an ill-formed byte through -- the
 * recipient's client decides what to do with a byte it cannot interpret -- but a
 * nickname is STORED and re-rendered into every prefix this node emits, so invalid
 * UTF-8 in one is a value that will be copied around the mesh for ever with no way
 * to tell what it was supposed to be." A realname is stored and re-rendered into
 * `311`, `301`, `352` and the extended-join for every member of every channel.
 *
 * THE COST, and it is a real one: `ā`, `café` and `日本語` are unaffected -- the walk
 * asks whether a continuation byte is EXPECTED before it looks at the byte, which is
 * why `0x81` inside `0xC4 0x81` is a letter and the identical byte on its own is a
 * control. What a realname can no longer carry is a byte sequence that is not UTF-8
 * at all, and no client sends one: the whole point of a realname is that a human
 * typed it. The other cost is one walk rather than one count, and the walk runs over
 * at most CONN_MAX_REALNAME bytes on a command a client sends once.
 *
 * TWO PASSES, and the length is why it is two: `conn_text_display_check()` walks
 * once for the verdict and once more for a sequence that stops at the string's end,
 * because the terminator is not a byte the loop is ever asked about. Over a
 * realname that is bounded at 255 bytes on a path that runs once per registration
 * and once per SETNAME. */
conn_realname_verdict_t conn_realname_check(const char *name)
{
    if (name == NULL) {
        return CONN_REALNAME_OK;
    }
    if (strlen(name) > (size_t)CONN_MAX_REALNAME) {
        return CONN_REALNAME_TOO_LONG;
    }
    if (conn_text_display_check(name) != CONN_DISPLAY_OK) {
        return CONN_REALNAME_BAD_BYTE;
    }
    return CONN_REALNAME_OK;
}

/* ---------------------------------------------------------------------------
 * THE LOG-INJECTION SET, defined once
 * ---------------------------------------------------------------------------
 * The whole of §9's hazard is these bytes: 0x07 rings a terminal's bell, and ESC
 * followed by `[` is a CSI sequence any terminal executes -- so a channel member
 * can rewrite an operator's screen through a log line, and a member's terminal can
 * be rewritten by another member. `message_parse_n()` refuses CR, LF and NUL
 * before any of this runs, so the range that reaches a caller is 0x01-0x08, 0x0b,
 * 0x0c, 0x0e-0x1f and 0x7f.
 *
 * DEL (0x7f) is in the set and that is not an accident of the C0 range: it is not
 * a control character to a terminal, it is an ordinary printable glyph in most
 * fonts, and it is invisible in a log. A byte that cannot be seen but can be
 * matched is worth refusing for a log the node has just described as the place
 * where refusals are made findable.
 *
 * SPACE (0x20) is OUT, and TAB (0x09) is IN. The argument for both is at the
 * header: space is the commonest byte in every field this touches, and TAB is a
 * rendering accident in a sentence somebody typed.
 *
 * BYTES >= 0x80 ARE OUT, permanently. That is the line that keeps UTF-8 intact:
 * every continuation byte of every multi-byte sequence is >= 0x80, so a filter
 * that reached them would corrupt non-ASCII text SILENTLY, which is a worse
 * failure than the injection this closes because the user cannot see it happen.
 *
 * STATIC, and that is a design statement rather than an encapsulation habit: it
 * is THE predicate, and it has exactly two callers in this file. Both are exposed
 * in connection.h because a field in another module must be able to ask the
 * question, and neither needs the byte test itself -- asking "how many" answers
 * "is there any" as `!= 0`, and the strip is the other operation. */
static int conn_byte_is_bad(char ch)
{
    const unsigned char u = (unsigned char)ch;

    return (u <= 0x1fu || u == 0x7fu) ? 1 : 0;
}

/* How many bytes of `s` are in the set. 0 for NULL, because NULL is not a string
 * and a caller that has no value has no bad byte -- which is what lets an empty
 * or absent parameter take the same path as a clean one. */
size_t conn_text_bad_count(const char *s)
{
    size_t n = 0;

    if (s == NULL) {
        return 0;
    }
    for (size_t i = 0; s[i] != '\0'; i++) {
        if (conn_byte_is_bad(s[i]) != 0) {
            n++;
        }
    }
    return n;
}

/* ---------------------------------------------------------------------------
 * conn_text_strip: A STORED VALUE, made safe to render to other people
 * ---------------------------------------------------------------------------
 * THE STRICT POLICY, through the same walk as the two strippers below, and this is the
 * one that found the last live leak: a TOPIC whose stored value held a bare
 * `0x80`-`0x9F` byte was broadcast to every member, because the old version of this
 * function only understood `conn_byte_is_bad()` -- C0 and DEL -- and let the whole
 * C1 range through. A raw `0x9B` is CSI on an 8-bit terminal, so a topic is exactly as
 * dangerous as a nickname and was being filtered against a narrower set.
 *
 * It is the SAME set the numeric-echo filter uses (`conn_text_strip_wire()`), and they
 * are the same function for the same reason `valid_nick()` and the nickname check share
 * one walk: two functions answering "which bytes are dangerous" is how they come to
 * disagree, and this tree has now been bitten by that three times.
 *
 * IT IS NOT `conn_text_strip_relay()`, which keeps the eight mIRC bytes. A stored topic
 * or away message is not message text: no client renders formatting codes out of a
 * topic, so keeping them would be keeping bytes that only look meaningful. The
 * difference is named at the walk's own enum rather than being discovered.
 *
 * ONE PASS, two outputs: the kept bytes go to `dst` and the KEPT COUNT comes back to
 * the caller, which derives "how many were dropped" by subtracting the input's own
 * strlen() from it. A caller that instead called `conn_text_bad_count()` first to get
 * that number would walk the same client-supplied string twice to learn one integer,
 * on a path that runs once per away change rather than once per packet.
 *
 * COST: one pass over a value the caller has already bounded, on a path that runs once
 * per stored-field write rather than once per packet. The `conn_text_bad_count()` the
 * callers use for their log lines is still a separate pass over the ORIGINAL string,
 * which is what makes their `bad_bytes=` figure a measurement of what the client sent
 * rather than of what survived. */
/* ---------------------------------------------------------------------------
 * conn_text_strip_relay: the KEEP half of the split, as a switch
 * ---------------------------------------------------------------------------
 * EIGHT BYTES, NAMED, rather than a range test -- because a range test is the
 * mistake waiting to happen here. `u >= 0x02 && u <= 0x1F` looks like the keep list
 * and is not: it would swallow 0x07 BEL and 0x1B ESC, which is the whole hazard,
 * and would return 0 for 0x01, which corrupts every CTCP. A reader who wants to add
 * a code to the keep list has to add it HERE, in the switch, where the list is
 * visible as a list.
 *
 * DEL is not here: it is a strip, handled by the caller below rather than here,
 * because 0x7F is not C0 and belongs to neither C0 group.
 */
static int relay_byte_kept(unsigned char u)
{
    switch (u) {
    case 0x01u: /* the CTCP delimiter -- removing it CORRUPTS rather than sanitises */
    case 0x02u: /* mIRC bold */
    case 0x03u: /* mIRC colour */
    case 0x0fu: /* mIRC plain */
    case 0x11u: /* mIRC mono */
    case 0x16u: /* mIRC reverse */
    case 0x1du: /* mIRC italic */
    case 0x1fu: /* mIRC underline */
        return 1;
    default:
        return 0;
    }
}

/* WHICH ASCII BYTES SURVIVE, and it is two answers rather than one because the
 * hazard and the semantics overlap in exactly eight bytes. `connection.h` states the
 * two policies and why they differ; this is the switch that implements the RELAY half,
 * and the WIRE half is "none of them", which is what makes the strict policy strict
 * rather than merely different. */
typedef enum {
    CONN_TEXT_WIRE = 0,  /* every C0 control goes: nothing is kept for cause */
    CONN_TEXT_RELAY = 1  /* the eight mIRC bytes stay: they are message semantics */
} conn_text_policy_t;

/* WHAT TO DO WITH ONE BYTE. Split out of the loop so the walk below is a walk and
 * not a decision tree, and so the rule for a single byte can be read in one place. */
enum {
    TEXT_EMIT = 0,  /* copy it */
    TEXT_DROP = 1,  /* remove it, and `*skip` more bytes with it */
    TEXT_FAULT = 2  /* report it as the string's verdict and stop (check mode) */
};

/* ---------------------------------------------------------------------------
 * ONE UTF-8 WALK, THREE ANSWERS, AND WHY IT LIVES HERE
 * ---------------------------------------------------------------------------
 * WHY IT IS HERE. `conn_byte_is_bad()` -- THE log-injection predicate this file's
 * header names as the single definition -- is here, and so are the two strip
 * operations built on it. The walk that tells a C1 control from the second half of a
 * Cyrillic letter is the SAME kind of thing: one definition of which bytes are
 * dangerous, asked rather than restated. Writing a second walker for the nickname
 * grammar in `message.c`, or a third for the numeric-echo filter in `reply.c`, is
 * exactly the divergence this file's own comment on `conn_realname_check()` warns
 * about -- "answering it from its own copy of `ch <= 0x1f || ch == 0x7f` is how the
 * two come to disagree about which bytes are dangerous", in a new costume.
 *
 * THREE ANSWERS BECAUSE THREE CALLERS NEED THREE DIFFERENT VERDICTS:
 *
 *   CONN_TEXT_WIRE   strip: a byte that can control a terminal goes, everything
 *                    else stays. Used where a value is RENDERED into a field the
 *                    sender will read again -- a numeric that echoes the client's
 *                    own argument back to it.
 *   CONN_TEXT_RELAY  strip, but the eight mIRC bytes STAY, because in message text
 *                    they are semantics rather than hazard.
 *   `verdict`        non-NULL: report instead of strip, and stop at the first fault.
 *                    Used where the value is STORED, so the caller can refuse rather
 *                    than quietly rewrite. It is always the STRICT policy: a
 *                    nickname is not message text and has no formatting to keep.
 *
 * THE ORDER IS THE DESIGN and it is the one thing a reader must not reshuffle. The
 * `*need` test comes FIRST because a continuation byte is defined by the byte before
 * it: `0x90` following a lead is the second half of a Cyrillic A and is EMITTED, and
 * the identical byte with nothing expecting it is a raw C1 and is DROPPED. Ask
 * anything about `u` on its own first and those two cases become indistinguishable,
 * which is the mistake that costs every Greek and Cyrillic message on the node --
 * and, on the nickname side, every `ā` on the network.
 *
 * `*skip` is how many extra bytes this one verdict consumes, which is 1 for the
 * encoded C1 pair and 0 for everything else. `at` points at the byte being judged,
 * so `at[1]` is the next one -- the terminator when `at` is the last byte, which is
 * why every range tested below excludes `0x00`.
 */
static int text_step(unsigned char u, const char *at, size_t *need, size_t *skip,
                     conn_text_policy_t policy, conn_display_verdict_t *verdict)
{
    *skip = 0;

    /* MID-SEQUENCE. */
    if (*need > 0u) {
        if (u >= 0x80u && u <= 0xbfu) {
            (*need)--;
            return TEXT_EMIT;
        }
        /* Not a continuation after all -- a truncated or malformed sequence. The lead
         * byte was already emitted, so this byte is re-examined on its own rather than
         * swallowed. Being permissive here only ever KEEPS a byte, which is the safe
         * direction in which to be wrong -- but in CHECK mode it is a fault, because a
         * nickname that claims a two-byte sequence and then does not finish it is
         * malformed and the whole point of the check is to refuse malformed. */
        *need = 0;
        if (verdict != NULL) {
            *verdict = CONN_DISPLAY_UTF8;
            return TEXT_FAULT;
        }
    }

    /* ASCII. The deny half of the split, plus DEL. ESC and BEL arrive here. */
    if (u < 0x80u) {
        if (u < 0x20u) {
            if (policy == CONN_TEXT_RELAY && relay_byte_kept(u) != 0) {
                return TEXT_EMIT;
            }
            if (verdict != NULL) {
                *verdict = CONN_DISPLAY_CONTROL;
                return TEXT_FAULT;
            }
            return TEXT_DROP;
        }
        if (u == 0x7fu) {
            if (verdict != NULL) {
                *verdict = CONN_DISPLAY_CONTROL;
                return TEXT_FAULT;
            }
            return TEXT_DROP;
        }
        return TEXT_EMIT;
    }

    /* THE ENCODED C1 PAIR. `0xC2` is the only lead byte a C1 control can carry in
     * UTF-8, and `0xC2` + `0x80-0x9F` is CSI and its relatives. Both bytes go, and
     * they are recognised BEFORE `0xC2` is treated as an ordinary lead -- otherwise
     * `0xC2 0x9B` would pass as a valid sequence and the 8-bit escape would survive,
     * which is the specific hole this case exists to close.
     *
     * AND IT IS ALSO U+0080-U+009F, which is the other half of why the same case
     * serves the nickname check: U+009B is CSI in Unicode, so a nickname carrying it
     * is carrying a control sequence whatever the encoding. */
    if (u == 0xc2u && (unsigned char)at[1] >= 0x80u && (unsigned char)at[1] <= 0x9fu) {
        if (verdict != NULL) {
            *verdict = CONN_DISPLAY_C1;
            return TEXT_FAULT;
        }
        *skip = 1;
        return TEXT_DROP;
    }

    /* A RAW C1: in 0x80-0x9F with nothing expecting a continuation. On an 8-bit
     * terminal `0x9B` IS CSI, so leaving it is the hazard this function exists to
     * remove. The alternative -- dropping 0x80-0x9F unconditionally -- would eat the
     * Cyrillic, the Greek and every accented character on the node, and it is the
     * mistake this code is most likely to be "simplified" into.
     *
     * THE NICKNAME HALF OF THAT ARGUMENT, because it is the same trade and the
     * nickname check has to make it deliberately rather than inherit it: `ā` is
     * `0xC4 0x81`, and `0x81` is inside this range. A byte-range refusal would eat
     * every accented Latin character on the network. What distinguishes them is the
     * `*need` state above and nothing else. */
    if (u >= 0x80u && u <= 0x9fu) {
        if (verdict != NULL) {
            *verdict = CONN_DISPLAY_C1;
            return TEXT_FAULT;
        }
        return TEXT_DROP;
    }

    /* AN ORDINARY MULTI-BYTE LEAD, and the only reason the Cyrillic survives --
     * with the FOUR LEADS THAT ARE NOT ORDINARY taken out of the ranges, and the
     * reason they are not ordinary is a filter-bypass vector.
     *
     * `0xE0 0x80` and `0xF0 0x80` are OVERLONG: they encode a code point a shorter
     * form already encodes, and `0xC0 0xAF` is the textbook example -- an overlong
     * SOLIDUS that decodes to `/` and compares equal to `/` in anything that
     * decodes before it compares. A filter that reads bytes sees something no
     * allowlist mentions; a filter that decodes sees `/`. Two filters disagreeing
     * about one value is the whole of that class of attack, and the cheapest way to
     * disagree is to let the encoding be non-canonical in the first place.
     *
     * `0xED 0xA0` is a SURROGATE HALF. U+D800-U+DFFF are reserved for UTF-16 and
     * have no UTF-8 encoding at all; the byte sequence is how the encoding says
     * "this is not a character", and a value that is not a character cannot be
     * displayed, compared or logged honestly.
     *
     * SO THE FOUR ARE EXCLUDED FROM THE RANGES AND CHECKED EXPLICITLY, each
     * against its own first-continuation bound, which is the tightest rule UTF-8
     * has: the SECOND byte of a sequence is what makes it minimal, and every other
     * byte is 0x80-0xBF. One check on one byte per sequence, and the ranges above
     * and below it stay three comparisons each.
     *
     * THE CHECK IS IN CHECK MODE ONLY, and that is a decision rather than an
     * omission. A STRIPPER may pass an ill-formed byte through -- the recipient's
     * client decides what to do with a byte it cannot interpret, and
     * `conn_text_logsafe()` withholds every non-printable byte whatever produced it
     * -- but a STORED value may not, because there is no copy to sanitise later and
     * an ill-formed sequence would be copied around the mesh for ever with no way
     * to tell what it was meant to be. That is the same split `valid_nick()` is
     * built on and the reason this predicate exists.
     *
     * COST: one comparison per multi-byte lead in check mode, and none at all in
     * strip mode. No new state and no second walk. */
    if (u == 0xe0u) {
        if (verdict != NULL && (unsigned char)at[1] < 0xa0u) {
            *verdict = CONN_DISPLAY_UTF8;
            return TEXT_FAULT;
        }
        *need = 2u;
        return TEXT_EMIT;
    }
    if (u == 0xedu) {
        if (verdict != NULL && (unsigned char)at[1] > 0x9fu) {
            *verdict = CONN_DISPLAY_UTF8;
            return TEXT_FAULT;
        }
        *need = 2u;
        return TEXT_EMIT;
    }
    if (u == 0xf0u) {
        if (verdict != NULL && (unsigned char)at[1] < 0x90u) {
            *verdict = CONN_DISPLAY_UTF8;
            return TEXT_FAULT;
        }
        *need = 3u;
        return TEXT_EMIT;
    }
    if (u == 0xf4u) {
        if (verdict != NULL && (unsigned char)at[1] > 0x8fu) {
            *verdict = CONN_DISPLAY_UTF8;
            return TEXT_FAULT;
        }
        *need = 3u;
        return TEXT_EMIT;
    }
    if (u >= 0xc2u && u <= 0xdfu) {
        *need = 1u;
        return TEXT_EMIT;
    }
    if ((u >= 0xe1u && u <= 0xecu) || (u >= 0xeeu && u <= 0xefu)) {
        *need = 2u;
        return TEXT_EMIT;
    }
    if (u >= 0xf1u && u <= 0xf3u) {
        *need = 3u;
        return TEXT_EMIT;
    }

    /* `0xC0` and `0xC1` can never lead a UTF-8 sequence -- they would only ever
     * encode an overlong NUL -- and `0xF5`-`0xFF` lie outside UTF-8 entirely. Neither
     * is named in the strip set and neither can move a cursor, so both are copied
     * unchanged. This function removes what is on the list, not everything it does
     * not recognise.
     *
     * IN CHECK MODE THEY ARE A FAULT, and that is the one place the two answers
     * genuinely differ. A stripper may pass invalid bytes through -- the recipient's
     * client is the thing that decides what to do with a byte it cannot interpret --
     * but a nickname is STORED and re-rendered into every prefix this node emits, so
     * invalid UTF-8 in one is a value that will be copied around the mesh forever with
     * no way to tell what it was supposed to be. */
    if (verdict != NULL) {
        *verdict = CONN_DISPLAY_UTF8;
        return TEXT_FAULT;
    }
    return TEXT_EMIT;
}

/* The walk, with the emit shared between the two strippers and the check. One
 * function rather than three so that the order above cannot be got right in one
 * place and wrong in another. */
static size_t conn_text_walk(char *dst, size_t cap, const char *src,
                             conn_text_policy_t policy,
                             conn_display_verdict_t *verdict)
{
    size_t kept = 0;
    size_t need = 0u;
    /* CHECK MODE WRITES NOTHING. `dst` is legitimately NULL there -- the caller wants
     * a verdict and no copy -- and the first version of this function indexed it
     * anyway, which is a null store on the first printable byte. It aborted every
     * registration on the node, and the symptom was fifty-six unrelated test
     * failures rather than anything that pointed here. The mode is now decided once,
     * from `verdict`, and the two are not allowed to disagree. */
    const int storing = (verdict == NULL);

    if (src == NULL) {
        if (storing != 0 && dst != NULL && cap > 0u) {
            dst[0] = '\0';
        }
        return 0;
    }
    for (size_t i = 0; src[i] != '\0'; i++) {
        const unsigned char u = (unsigned char)src[i];
        size_t skip = 0u;
        int step;

        step = text_step(u, src + i, &need, &skip, policy, verdict);
        if (step == TEXT_FAULT) {
            return 0u;
        }
        if (step == TEXT_DROP) {
            i += skip;
            continue;
        }
        if (storing == 0) {
            continue;
        }
        /* The bound is a SAFETY net on the same terms as conn_text_strip()'s. Every
         * caller has already applied its own length bound and stripping only removes
         * bytes, so this cannot fire. */
        if (kept + 1u >= cap) {
            break;
        }
        dst[kept] = (char)u;
        kept++;
    }
    if (storing != 0) {
        dst[kept] = '\0';
    }
    return kept;
}

size_t conn_text_strip(char *dst, size_t cap, const char *src)
{
    return conn_text_walk(dst, cap, src, CONN_TEXT_WIRE, NULL);
}

size_t conn_text_strip_relay(char *dst, size_t cap, const char *src)
{
    return conn_text_walk(dst, cap, src, CONN_TEXT_RELAY, NULL);
}

size_t conn_text_strip_wire(char *dst, size_t cap, const char *src)
{
    return conn_text_walk(dst, cap, src, CONN_TEXT_WIRE, NULL);
}

conn_display_verdict_t conn_text_display_check(const char *s)
{
    conn_display_verdict_t verdict = CONN_DISPLAY_OK;

    if (s == NULL) {
        return CONN_DISPLAY_OK;
    }
    /* A TRUNCATED SEQUENCE AT THE END is the one fault `text_step()` cannot see,
     * because the terminator is not a byte it is ever asked about: the loop stops at
     * the NUL and `*need` is still positive. That is a real fault and it is the one
     * a nickname must not have, so the residue is checked here rather than left to
     * be discovered as a nickname that renders differently on every hop. */
    (void)conn_text_walk(NULL, 0u, s, CONN_TEXT_WIRE, &verdict);
    if (verdict != CONN_DISPLAY_OK) {
        return verdict;
    }
    {
        /* The same walk, one more time, asking only about the tail. Two passes over
         * a nickname is cheap -- a nickname is at most IRC_MAX_NICK bytes and this
         * runs once per registration and once per NICK -- and the alternative is a
         * third copy of the "how many continuation bytes does this sequence still
         * expect" arithmetic, which is the thing this whole refactor exists to
         * prevent. */
        size_t need = 0u;
        size_t skip = 0u;

        for (size_t i = 0; s[i] != '\0'; i++) {
            (void)text_step((unsigned char)s[i], s + i, &need, &skip, CONN_TEXT_WIRE,
                            NULL);
        }
        if (need > 0u) {
            return CONN_DISPLAY_UTF8;
        }
    }
    return CONN_DISPLAY_OK;
}

/* ---------------------------------------------------------------------------
 * conn_text_logsafe, and the one decision it makes
 * ---------------------------------------------------------------------------
 * The test is `conn_byte_is_bad()` and nothing else, so this function and
 * `conn_text_bad_count()` cannot disagree about a string: a caller that prints
 * `s` here and reports `conn_text_bad_count(s)` bad bytes is describing one set,
 * not two.
 *
 * PRINTABLE ASCII, 0x20 to 0x7e, is the accepted range and that is wider than the
 * strictest reading on purpose. A verb, a nickname, a channel name, a server mask
 * and an opaque token are all ASCII, and the whole value of a log line that names
 * one of them is that the name is readable. So the value is kept whenever keeping
 * it is safe, and the function's job is to know exactly when that is.
 *
 * `-` RATHER THAN AN EMPTY STRING, because `field=` with nothing after it reads as
 * a rendering bug on a log line and `-` is already this tree's spelling for "there
 * was no value" at every other site -- `ping: token=-` for an absent PING argument
 * is the same convention.
 *
 * WHAT IT CANNOT DO is make an unsafe value safe by rewriting it. A caller that
 * wants a mutated value wants `conn_text_strip()`, and a caller that has already
 * stripped a field should not reach for this at all: the value is then printable
 * and the two would agree, at the cost of a second pass. */
size_t conn_text_logsafe(char *out, size_t cap, const char *s)
{
    if (out == NULL || cap < 2u) {
        return 0;
    }
    if (s == NULL || s[0] == '\0') {
        out[0] = '-';
        out[1] = '\0';
        return 1u;
    }
    for (size_t i = 0; s[i] != '\0'; i++) {
        const unsigned char u = (unsigned char)s[i];

        if (conn_byte_is_bad((char)u) != 0 || u > 0x7eu) {
            out[0] = '-';
            out[1] = '\0';
            return 1u;
        }
        /* LENGTH IS THE THIRD REASON FOR WITHHOLDING, and it is checked in the same
         * pass so a caller learns about it without a second walk. One `-` then means
         * three things -- absent, unsafe, or too long for the field -- and the `len=`
         * every caller prints beside it is what tells the last two apart. */
        if (i + 2u > cap) {
            out[0] = '-';
            out[1] = '\0';
            return 1u;
        }
    }
    (void)snprintf(out, cap, "%s", s);
    return strlen(out);
}
