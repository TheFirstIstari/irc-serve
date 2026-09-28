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
 * without what did arrive is the least useful failure message there is. */
int tc_expect(test_client_t *c, const char *needle, int timeout_ms);

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

#endif /* TEST_HARNESS_IRC_CLIENT_H */
