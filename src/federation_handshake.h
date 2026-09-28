#ifndef IRC_FEDERATION_HANDSHAKE_H
#define IRC_FEDERATION_HANDSHAKE_H

/* Federation link handshake state machine.
 *
 * Ownership / threading: every function operates on an explicit,
 * caller-owned context (`handshake_ctx_t`). There is NO hidden module-global
 * handshake state. A context must not be shared or used from more than one
 * thread at a time; the caller owns its lifetime and is responsible for
 * keeping the context alive between calls. This matches the single-threaded
 * ownership contract of the server core.
 *
 * State model:
 *     INIT -> HANDSHAKE_SENT -> ESTABLISHED
 *       |        |   |         |
 *       |        +---+         +--> FAILED
 *       `---------+---`----------> TIMED_OUT (only valid from HANDSHAKE_SENT)
 *
 * All transition functions are NULL-safe: passing NULL returns an error and
 * leaves no state behind. Rejected transitions are observable via a non-zero
 * return value and leave the context state unchanged.
 *
 * Note for callers: a context reaching HANDSHAKE_SENT means the local side
 * has emitted its handshake; it does NOT mean the peer acknowledged. Only
 * ESTABLISHED reflects a completed (federated) link.
 */

typedef enum {
    INIT = 0,
    HANDSHAKE_SENT = 1,
    ESTABLISHED = 2,
    FAILED = 3,
    TIMED_OUT = 4
} handshake_state_t;

typedef struct handshake_ctx {
    handshake_state_t state;
} handshake_ctx_t;

/* Initialise a fresh context to INIT. NULL-safe (no-op). */
void handshake_init(handshake_ctx_t *ctx);

/* Return the current state. NULL-safe (returns INIT). */
handshake_state_t handshake_state(const handshake_ctx_t *ctx);

/* Transitions. Each returns 0 on success, -1 on a rejected/invalid
 * transition (or NULL argument). A rejected transition is observable via the
 * return value and leaves the state unchanged. */
int handshake_send(handshake_ctx_t *ctx);    /* INIT -> HANDSHAKE_SENT */
int handshake_receive(handshake_ctx_t *ctx); /* HANDSHAKE_SENT -> ESTABLISHED */
int handshake_fail(handshake_ctx_t *ctx);    /* HANDSHAKE_SENT | ESTABLISHED -> FAILED */
int handshake_timeout(handshake_ctx_t *ctx); /* HANDSHAKE_SENT -> TIMED_OUT */

/* Reset a context back to INIT so a failed/timed-out exchange can be
 * retried. NULL-safe (no-op). */
void handshake_reset(handshake_ctx_t *ctx);

/* Returns 0 (linked/live) only when the handshake has reached ESTABLISHED,
 * otherwise non-zero (not linked). NULL-safe: NULL context reports not
 * linked. */
int heartbeat_check(const handshake_ctx_t *ctx);

#endif /* IRC_FEDERATION_HANDSHAKE_H */
