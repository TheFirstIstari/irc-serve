/* irc_client.h -- the wire-level client the integration tests assert against.
 *
 * Authority: docs/SERVER_DESIGN.md 6.1 (harness) and 6.3 (no flaky sleeps).
 *
 * These tests assert on wire output rather than on internals, so they survive a
 * refactor of the server. That only works if the client is a real socket peer
 * and not a stub, which is why this is a blocking TCP client against a node
 * that was forked into its own process: nothing here reaches into irc_core.
 *
 * ---------------------------------------------------------------------------
 * WHY THERE IS NO FIXED SLEEP ANYWHERE IN THIS FILE
 * ---------------------------------------------------------------------------
 * A fixed sleep is the leading cause of CI flake: it is too short on a loaded
 * runner and wastes time on a fast one, and it converts a race into a test
 * that passes locally. Every wait here is a DEADLINE wait: select() with a
 * short timeout in a loop, re-checking a condition, giving up when the deadline
 * expires. The short select() timeout is a polling interval, not an assumption
 * about how long the other side takes. Deadlines here are in SECONDS, because
 * they must tolerate a loaded CI machine, while still failing fast when the
 * thing being waited for never happens.
 */
#ifndef TEST_HARNESS_IRC_CLIENT_H
#define TEST_HARNESS_IRC_CLIENT_H

#include <stddef.h>

/* A connected test client. `buf` accumulates EVERY byte received, so a test can
 * compare a whole response byte-for-byte and so a failure can print what
 * actually arrived instead of just "timed out". */
typedef struct {
    int    fd;
    char  *buf;
    size_t len;
    size_t cap;
    /* Set once any read on this connection has seen the peer close, and NOT reset
     * afterwards. Every read path reports a close through its own `*eof` out-param,
     * which means a caller that reads in a loop and ignores one of those flags has
     * silently thrown the fact away -- and the next call then waits for a reply that
     * can no longer arrive and reports a TIMEOUT for a connection that closed two
     * reads ago. Holding the fact here makes it non-lossy, which is what
     * tc_closed() is for. */
    int    closed;
} test_client_t;

/* Prepare an unconnected client. tc_connect() zeroes the client itself, so this
 * is only needed to have a valid client in hand BEFORE connecting -- which is
 * what makes tc_close() safe on a client whose connect failed or was never
 * attempted. Calling it is the habit worth keeping: tc_close() on a struct that
 * was never connected and never initialised frees a garbage pointer. */
void tc_init(test_client_t *c);

/* Connect to 127.0.0.1:`port`, blocking with a generous internal timeout.
 * Returns 0 on success, -1 on failure. `port` is the ephemeral port the node
 * reported, which is why tests never collide and may run in parallel.
 *
 * The client is zeroed first, so this is safe on an uninitialised struct. */
int tc_connect(test_client_t *c, int port);

/* As tc_connect(), but requests SO_RCVBUF = `rcvbuf` bytes before connecting.
 * Pass 0 to keep the kernel default.
 *
 * CAVEAT, learned the hard way: this is a REQUEST, not a guarantee. macOS
 * re-autotunes the receive buffer after the handshake and reports a figure far
 * above what was asked for, so it cannot be used to force a peer's send() to
 * come up short. Nor can the value be read back and compared: Linux stores and
 * reports roughly double the request and floors it, so a test that pinned a
 * buffer and then asserted on the read-back number would be macOS-only by
 * construction (that is exactly how test_partial_write failed on Linux).
 *
 * A test that needs a peer's send() to come up short has to make the condition
 * unavoidable instead of predicting it -- see the dispatch in
 * test_partial_write.c, which tops the write queue up to its cap and pumps
 * until the socket refuses a single byte. Nothing here asserts on a
 * kernel-reported number, and nothing should. */
int tc_connect_rcvbuf(test_client_t *c, int port, int rcvbuf);

/* Send `line` with the CRLF terminator RFC 1459 2.3 requires. Returns 0 on
 * success, -1 on failure. Retries on a short write, because a test that cannot
 * deliver its own input line is not testing the server. */
int tc_send(test_client_t *c, const char *line);

/* Send exactly `n` bytes with no terminator added, for framing tests that need
 * to control the bytes on the wire. */
int tc_send_raw(test_client_t *c, const char *bytes, size_t n);

/* Wait until `needle` appears in everything received so far, or until
 * `timeout_ms` expires. Returns 0 on success, -1 on timeout.
 *
 * The search is over the ACCUMULATED buffer, not the latest chunk, so a needle
 * split across two TCP segments is found. On failure this prints the bytes
 * received (escaped, truncated) to stderr, because "timed out waiting for X"
 * without what did arrive is the least useful failure message there is.
 *
 * A TIMEOUT IS A TIMEOUT, NOT A HANG. Past the deadline this returns -1 rather
 * than continuing to wait, so a needle that is never going to arrive fails the
 * test promptly instead of spinning until the runner kills it. `needle` is a
 * substring of the accumulated stream, not a line: a test asserting the exact
 * bytes of a reply should include the terminating CRLF in `needle`, because
 * that is what proves the line is terminated on the wire rather than being a
 * prefix of a longer one. */
int tc_expect(test_client_t *c, const char *needle, int timeout_ms);

/* Read ONE COMPLETE LINE and hand back its payload.
 *
 * Wait until a line arrives whose text begins with `prefix`, copy that line's
 * text -- the whole line, without the CRLF -- into `out` (NUL-terminated), set
 * `*len` to its length, and return 0. -1 on timeout.
 *
 * WHY THIS EXISTS, and it is a bug class rather than a convenience. It is now the
 * THIRD time in this suite that a test has needed "the reply, as a string, with
 * the line boundary proved" and written it by hand, and the two hand-rolled
 * versions were both wrong in different ways:
 *
 *   tc_expect() with the CRLF inside the needle proves the line is TERMINATED but
 *   says nothing about where it STARTS, so it can be satisfied by a longer line
 *   that happens to contain the text. Hand-rolling the other half -- finding the
 *   needle with strstr() and then checking the byte before it -- is what
 *   tests/integration/test_cap_negotiation.c did, and it got the offset wrong
 *   twice before it was right.
 *
 *   Copying the payload into a caller buffer with snprintf() and then walking it
 *   with str*() is what that case did next, and it read one byte PAST the end of
 *   what it wrote: the buffer was 2048 bytes, the payload was 180, and the token
 *   walk stepped off the end of the string onto an uninitialised byte. On the
 *   author's machine that byte was zero; on a GitHub runner it was not, and
 *   `CAPNegotiation` failed in all four ci_macos cells with a capability count
 *   one too high. Passing `*len` back is the fix: a caller that walks a COUNTED
 *   string cannot read past it, and one that walks it with str*() has been handed
 *   the length for a reason.
 *
 * So the three properties this buys, each of which a hand-rolled version got
 * wrong at least once:
 *
 *   1. THE LINE MUST BE TERMINATED. A partial line is not a match, however much
 *      of the prefix has arrived. This is what makes the answer independent of how
 *      the reply was split across TCP segments -- a question that never needed
 *      asking once the terminator is required.
 *   2. THE PREFIX MUST BE AT A LINE BOUNDARY. The bytes before it must be the
 *      start of the buffer or the LF of the previous line's CRLF, so a reply that
 *      merely CONTAINS the text cannot satisfy it.
 *   3. THE CALLER GETS A LENGTH. See above.
 *
 * `prefix` is matched case-SENSITIVELY and against the line's text as it arrived,
 * which for this tree's formatter is the wire spelling. An empty prefix matches
 * the next complete line, which is occasionally what a test wants.
 *
 * This does NOT consume the line: the accumulated buffer is unchanged, so a test
 * can still `strstr()` the whole stream afterwards, exactly as before. */
int tc_read_line(test_client_t *c, const char *prefix, char *out, size_t cap,
                 size_t *len, int timeout_ms);

/* As tc_read_line(), but the scan starts at `from` rather than at the beginning
 * of the buffer, so a caller can walk SUCCESSIVE matching lines.
 *
 * WHY IT IS A SEPARATE ENTRY POINT rather than a flag on the first one: a test that
 * wants the first match writes `tc_read_line()`, and a test that wants the third
 * writes `tc_read_line_from(2 * CAP_LS_MAX, ...)` or whatever the offset is -- the
 * offset is something the CALLER computes and owns, and a function that hid it
 * behind a "skip the first N" argument would be asking the caller to do the same
 * arithmetic with less information.
 *
 * `from` past the end of the buffer is not an error: it simply finds nothing and
 * times out, which is what a caller that has consumed everything should see. */
int tc_read_line_from(test_client_t *c, size_t from, const char *prefix, char *out,
                      size_t cap, size_t *len, int timeout_ms);

/* Wait for the server to close its half. Returns 0 when a clean EOF was
 * observed (recv() returned 0), -1 on timeout, -2 on a timeout where data had
 * arrived but the close never did, and -3 if the connection was reset.
 *
 * EOF and ECONNRESET are different outcomes and the difference is the point: a
 * clean close is a FIN, while a reset is the kernel discarding an unread queue.
 * A test asserting "closed cleanly" must not accept both. */
int tc_expect_eof(test_client_t *c, int timeout_ms);

/* Read exactly `n` bytes into `dst`, or fail. Returns 0 on success, -1 on
 * timeout or a short read. This is how a byte-for-byte comparison is done
 * without depending on how the bytes were split across segments. */
int tc_read_exact(test_client_t *c, char *dst, size_t n, int timeout_ms);

/* Half-close: signal EOF to the server while keeping the read side open. This
 * is how a test asks the node to notice a client hangup. */
int tc_half_close(test_client_t *c);

/* Everything received so far, NUL-terminated for convenience. Do not modify. */
const char *tc_buffer(const test_client_t *c);
size_t tc_received(const test_client_t *c);

/* Close and release. Safe on a zeroed or already-closed client. */
void tc_close(test_client_t *c);

/* ---------------------------------------------------------------------------
 * THE PUMP HOOK, and why a socket wait needs one
 * ---------------------------------------------------------------------------
 * Every deadline loop in this file blocks on ONE descriptor: the client socket.
 * A two-node test also has child processes whose stdout the parent has to keep
 * reading, and a loop that only ever selects on the socket reads nobody else's
 * output for as long as it waits.
 *
 * That is not a tidiness issue. A child writes its `[observable]` and
 * `[fixture] stats` lines to a PIPE, and a pipe holds a fixed amount (65536
 * bytes on both Linux and macOS). A child that fills it blocks inside its own
 * event loop -- in node_fixture.c the stats republication happens in the tick
 * hook, so the block is inside `poll_loop_step()` -- and a node that is blocked
 * there serves nothing: no accept, no read, no reply to the very client this
 * loop is waiting on. The wait then runs out its deadline against a node that is
 * not slow but wedged, and reports it as a protocol failure.
 *
 * So this file calls a hook once per iteration of every deadline loop, and
 * node_fixture.c installs one that drains every live child. The hook is what
 * makes "the parent is always reading" true no matter which wait is running;
 * without it the property holds only by accident of what the test happened to
 * call next.
 */
typedef void (*tc_pump_fn)(void);

/* Run the installed pump hook ONCE, now.
 *
 * It exists for a wait that is not one of this file's own loops. Every wait in
 * irc_client.c calls pump_hook() itself, but a wait over an SSL object cannot use
 * them -- see the block above, which explains why after a handshake the decrypted
 * bytes are inside OpenSSL rather than in the socket. tests/harness/tls_fixture.c's
 * tf_tls_expect() is that wait, and without this it would stop draining the child
 * nodes' stdout, so a node that fills its 64 KiB pipe would wedge inside its own
 * event loop while the test waited for it to answer. */
void tc_pump(void);

/* Run the installed pump hook ONCE, now.
 *
 * It exists because a wait that is not one of this file's own loops still has to
 * keep the parent reading, and irc_client.h's own block above says why that is not
 * a tidiness matter: a child's stdout is a 64 KiB pipe, a child that fills it
 * blocks INSIDE its event loop, and then it serves nobody. A test that waits on a
 * socket of its OWN -- rather than through tc_expect() -- has no way to keep that
 * true, and tests/harness/tls_fixture.c's tf_tls_expect() is exactly that: it waits
 * on an SSL object with its own select() loop because after a handshake the
 * decrypted bytes are inside OpenSSL and reading the descriptor would return the
 * NEXT record rather than the one being waited for.
 *
 * So it calls this once per iteration. The alternative -- letting each fixture grow
 * its own reference to the harness's internals -- is worse, because the hook is
 * installed by node_fixture.c and the two would have to agree about it by
 * convention. */
void tc_pump(void);

/* Install the callback every deadline loop calls to keep unrelated readers
 * moving. NULL removes it. tc_init()/tc_connect() do NOT clear it: it belongs to
 * the process, not to a connection. */
void tc_set_pump_hook(tc_pump_fn fn);

/* Drain this client's socket until the deadline passes, waiting on the socket
 * and on the installed pump hook at the same time. Returns 0 if nothing was
 * read before the deadline, 1 if bytes were appended, -1 on a hard error, and
 * sets `*eof` when the peer closed. */
int tc_drain(test_client_t *c, int timeout_ms, int *eof);

/* Read every byte the kernel ALREADY has for this connection -- without waiting for
 * more -- appending to the client's accumulated buffer. Returns the number of bytes
 * appended, 0 when there was nothing to read, or -1 on a hard error. `*eof` is set
 * when the peer closed.
 *
 * ---------------------------------------------------------------------------
 * WHY IT EXISTS, and it is not a convenience
 * ---------------------------------------------------------------------------
 * The other two ways to read this socket each break one thing a test needs:
 *
 *   `tc_drain()` COMPACTS. Its first act in every iteration is to shift the unread
 *   tail down over the accumulated history, so after it returns `tc_buffer()` holds
 *   only what arrived since the last call. A test that wants to scan everything a
 *   connection received cannot use it, and cannot find out that it lost the bytes:
 *   the scan simply sees less.
 *
 *   `tc_expect()` waits, and reports "TIMEOUT after N ms" when it breaks out of its
 *   loop on EOF -- which it does, because a close ends the wait. A test that closes
 *   connections on purpose then gets a report claiming a timeout that did not
 *   happen, which sends the reader looking for a hang.
 *
 * What is needed is the read without either property, and one caller needed it
 * badly enough to add it: tests/integration/test_terminal_sweep.c sends thousands of
 * lines per probe and has to keep BOTH ends moving -- the node's stdout pipe and
 * this socket -- or the node blocks inside write() and stops serving the very client
 * being probed. `MSG_DONTWAIT` is what makes the read non-blocking without a select()
 * round trip, and it costs one flag word. */
int tc_read_available(test_client_t *c, int *eof);

/* Has ANY read on this connection already seen the peer close? Sticky: it stays true
 * once it becomes true, because the close is a fact about the connection rather than
 * about one read. See the field's own comment. */
int tc_closed(const test_client_t *c);

#endif /* TEST_HARNESS_IRC_CLIENT_H */
