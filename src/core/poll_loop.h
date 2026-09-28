/* poll_loop.h -- the single-threaded poll() loop (3.4).
 *
 * Authority: docs/SERVER_DESIGN.md 3.4. Not epoll/kqueue: one portable file,
 * and the FD_SETSIZE ceiling is accepted for this scope rather than
 * optimised away before anything has been measured.
 */
#ifndef IRC_CORE_POLL_LOOP_H
#define IRC_CORE_POLL_LOOP_H

#include <stdint.h>

#include "core/server.h"

/* The loop's cadence. 3.4 fixes a 50 ms tick; 3.4 also requires that the tick
 * is what drives time, so every future timeout in the node hangs off this
 * number rather than off a handler's own clock read. */
#define POLL_TICK_MS 50

/* Request a clean stop. Async-signal-safe and callable from a signal handler,
 * which is how node_main wires SIGTERM and SIGINT to it. Latched, so a signal
 * that arrives while poll() is blocked is not lost. */
void poll_loop_request_stop(void);

/* Has a stop been requested? */
int poll_loop_stopped(void);

/* Clear the stop latch. Paired with poll_loop_request_stop() for a caller that
 * stops a loop and then starts one again -- a test process that runs a node more
 * than once, or a future embedder. poll_loop_run() never needs it. */
void poll_loop_clear_stop(void);

/* Run one iteration: build the poll sets, wait up to `timeout_ms`, then do the
 * accept, read, write, dial-progress and reap work for that iteration, and
 * finally the tick. Returns 0 on a completed iteration, 1 when poll() was
 * interrupted by a signal (EINTR -- counted, and NOT a failure), and -1 on a
 * fatal error. A signal during the wait must never terminate the loop, so 1 is
 * an ordinary outcome and the caller keeps going.
 *
 * poll_loop_run() below is nothing but this in a loop. It is a separate function
 * because the eight steps of an iteration are the unit of reasoning here -- the
 * reaper's position in the order is the whole design -- and because a caller
 * that wants to drive the loop itself (a one-iteration smoke check, a future
 * single-stepping debugger) should not have to reimplement the ordering. No
 * caller outside this file needs it today. */
int poll_loop_step(server_t *s, int timeout_ms);

/* Run until poll_loop_request_stop() is called, then shut the node down and
 * return 0. Never returns on a signal: an interrupted poll is retried. */
int poll_loop_run(server_t *s);

#endif /* IRC_CORE_POLL_LOOP_H */
