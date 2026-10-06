/* peer_fixture.h -- a raw PEER socket, for tests that stand in for the other end of
 * a federation link.
 *
 * WHY IT IS IN THE HARNESS AND NOT IN ONE TEST
 * ---------------------------------------------
 * Two tests need it and they need it IDENTICALLY: `test_fed_guards.c`, which drives
 * the pre-auth guards, and `test_terminal_sweep` (the peer sweep), which drives
 * every marker byte down a live link. A second copy of the handshake would be a
 * second definition of "a peer this node accepted", and the two could disagree about
 * it in exactly the way that makes a sweep vacuous -- the sweep opens a link the
 * node never really established, every probe is answered by nothing, and the sweep
 * passes because it never found a byte in output that was never produced.
 *
 * WHAT IT IS AND IS NOT
 * ---------------------
 * It is a socket and four helpers. It is NOT a peer implementation: there is no
 * burst, no roster, no dedup store and no state machine here. The node's own
 * handshake is answered by `pf_read_until()` matching a literal, which is enough
 * because the claim this node makes is fixed in a test.
 *
 * The one thing that IS a policy decision rather than a helper: `pf_open()` reads
 * node A's claim BEFORE answering it, and asserts the link reached ESTABLISHED
 * before returning. Without both, "the peer was accepted" is satisfied by a node
 * that never sent a handshake, and everything a caller asserts afterwards is about
 * a link that does not exist.
 */
#ifndef PEER_FIXTURE_H
#define PEER_FIXTURE_H

#include <stddef.h>

/* A connected peer socket and the loopback port the node dialled. */
typedef struct {
    int fd;   /* the accepted socket, or -1 */
    int port; /* the port the test asked the node to dial */
} pf_peer_t;

void pf_peer_init(pf_peer_t *p);

/* A listening socket on 127.0.0.1 with the kernel's choice of port, written back to
 * `port_out`. Returns the descriptor, or -1. The caller closes it as soon as it has
 * accepted: leaving a second listener open would mean a second dial could be
 * accepted by accident, and every "there is one link" claim in the callers rests on
 * there being exactly one. */
int pf_listen_loopback(int *port_out);

/* Accept one connection, or -1 on the deadline. EINTR retries. */
int pf_accept_deadline(int listen_fd, int timeout_ms);

/* Read until EVERY needle has appeared, or the deadline passes. All the needles in
 * ONE call, because the accumulated buffer is local: a second call starts from
 * nothing and can never see the bytes the first consumed. Returns 0 on success. */
int pf_read_until(int fd, const char *const *needles, size_t nneedles,
                  int timeout_ms);

/* Write a whole buffer. `n` is explicit rather than `strlen` because the sweep has
 * lines containing bytes that are not printable and one containing an embedded
 * NUL-adjacent shape. Returns 0 on success. */
int pf_send_raw(int fd, const char *bytes, size_t n);

/* Write `line` with CRLF appended. */
int pf_send_line(int fd, const char *line);

/* Copy whatever has arrived into `dst` without blocking, and NUL-terminate.
 * Returns the number of bytes copied, or -1. Non-blocking BY DESIGN: the sweep
 * reads a peer's output while the node is still running, and a read that waits is
 * how a test stops being a test and becomes a hang. */
long pf_drain(int fd, char *dst, size_t cap);

/* How many times `needle` appears in `buf`. */
size_t pf_times_seen(const char *buf, const char *needle);

/* Milliseconds on a monotonic clock. Exposed because a caller that stamps two
 * events wants them on the same clock as the reads above. */
unsigned long long pf_now_ms(void);

#endif /* PEER_FIXTURE_H */
