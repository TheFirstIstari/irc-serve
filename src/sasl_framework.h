#ifndef IRC_SASL_FRAMEWORK_H
#define IRC_SASL_FRAMEWORK_H

#include <stddef.h>

/* Observable SASL framework: ABORTED -> IN_PROGRESS -> COMPLETED | FAILED.
 *
 * The framework is a pure observable state machine: every entry point mutates
 * a caller-owned context and reports the resulting state. There is no network
 * I/O, no timers and no hidden module-global state. Each function is
 * NULL-safe in the sense documented per function below; a context must not be
 * shared across threads. */

typedef enum {
    SASL_ABORTED = 0,
    SASL_IN_PROGRESS = 1,
    SASL_COMPLETED = 2,
    SASL_FAILED = 3
} sasl_state_t;

typedef struct {
    sasl_state_t state;
    char mechanism[32];
    char authzid[64];
    char authcid[64];
    int step_count;
    int last_error;
} sasl_ctx_t;

/* Zero `ctx` and set state to SASL_ABORTED. `mechanism` is copied (truncating)
 * when non-NULL. */
void sasl_init(sasl_ctx_t *ctx, const char *mechanism);

/* Start the mechanism. Only valid from SASL_ABORTED, which it consumes; from
 * any other state it returns that state unchanged. Returns the new state. */
sasl_state_t sasl_start(sasl_ctx_t *ctx);

/* Advance the exchange one step. Only valid from SASL_IN_PROGRESS, from which
 * the second step transitions to SASL_COMPLETED. `client_out`/`out_len` are
 * optional: when both are non-NULL, *out_len is set to 0. Returns the new
 * state. */
sasl_state_t sasl_step(sasl_ctx_t *ctx, const char *server_data, size_t len,
                       char *client_out, size_t *out_len);

/* Force the context to SASL_ABORTED, recording `error_code` in last_error. */
sasl_state_t sasl_abort(sasl_ctx_t *ctx, int error_code);

/* Force the context to SASL_FAILED, recording `error_code` in last_error. */
sasl_state_t sasl_fail(sasl_ctx_t *ctx, int error_code);

/* Read-only current state. */
sasl_state_t sasl_get_state(const sasl_ctx_t *ctx);

/* Drive the full observable lifecycle on a local context and assert its
 * internal expectations. Returns 1 when every path behaved as documented, 0
 * otherwise. */
int sasl_state_machine(void);

#endif /* IRC_SASL_FRAMEWORK_H */
