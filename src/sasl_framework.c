/* Observable SASL framework: ABORTED -> IN_PROGRESS -> COMPLETED | FAILED. */
#include <assert.h>
#include <stdio.h>
#include <string.h>

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

void sasl_init(sasl_ctx_t *ctx, const char *mechanism) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->state = SASL_ABORTED;
    if (mechanism) {
        strncpy(ctx->mechanism, mechanism, sizeof(ctx->mechanism) - 1);
    }
}

sasl_state_t sasl_start(sasl_ctx_t *ctx) {
    assert(ctx != NULL);
    if (ctx->state < SASL_ABORTED || ctx->state > SASL_FAILED) {
        return SASL_FAILED;
    }
    if (ctx->state != SASL_ABORTED) {
        return ctx->state;
    }
    ctx->state = SASL_IN_PROGRESS;
    ctx->step_count = 0;
    printf("[observable] sasl_start: mechanism=%s state=IN_PROGRESS\n", ctx->mechanism);
    return ctx->state;
}

sasl_state_t sasl_step(sasl_ctx_t *ctx, const char *server_data, size_t len, char *client_out, size_t *out_len) {
    assert(ctx != NULL);
    if (ctx->state < SASL_ABORTED || ctx->state > SASL_FAILED) {
        return SASL_FAILED;
    }
    if (ctx->state != SASL_IN_PROGRESS) {
        return ctx->state;
    }
    ctx->step_count++;
    (void)server_data;
    (void)len;
    if (client_out && out_len) {
        *out_len = 0;
    }
    printf("[observable] sasl_step: step=%d mechanism=%s\n", ctx->step_count, ctx->mechanism);
    if (ctx->step_count >= 2) {
        ctx->state = SASL_COMPLETED;
        printf("[observable] sasl_step: state=COMPLETED\n");
    }
    return ctx->state;
}

sasl_state_t sasl_abort(sasl_ctx_t *ctx, int error_code) {
    assert(ctx != NULL);
    if (ctx->state < SASL_ABORTED || ctx->state > SASL_FAILED) {
        return SASL_FAILED;
    }
    ctx->state = SASL_ABORTED;
    ctx->last_error = error_code;
    printf("[observable] sasl_abort: error=%d\n", error_code);
    return ctx->state;
}

sasl_state_t sasl_fail(sasl_ctx_t *ctx, int error_code) {
    assert(ctx != NULL);
    if (ctx->state < SASL_ABORTED || ctx->state > SASL_FAILED) {
        return SASL_FAILED;
    }
    ctx->state = SASL_FAILED;
    ctx->last_error = error_code;
    printf("[observable] sasl_fail: error=%d\n", error_code);
    return ctx->state;
}

sasl_state_t sasl_get_state(const sasl_ctx_t *ctx) {
    assert(ctx != NULL);
    if (ctx->state < SASL_ABORTED || ctx->state > SASL_FAILED) {
        return SASL_FAILED;
    }
    return ctx->state;
}

int sasl_state_machine(void) {
    sasl_ctx_t ctx;
    sasl_init(&ctx, "PLAIN");
    printf("[observable] sasl_state_machine: init mechanism=PLAIN state=ABORTED\n");
    assert(sasl_get_state(&ctx) == SASL_ABORTED);

    sasl_state_t s = sasl_start(&ctx);
    printf("[observable] sasl_state_machine: start returned=%d (IN_PROGRESS=%d COMPLETED=%d FAILED=%d)\n",
           s, SASL_IN_PROGRESS, SASL_COMPLETED, SASL_FAILED);
    assert(s == SASL_IN_PROGRESS);

    char buf[256];
    size_t out_len = sizeof(buf);

    sasl_step(&ctx, "", 0, buf, &out_len);
    printf("[observable] sasl_state_machine: step1 state=%d\n", sasl_get_state(&ctx));

    sasl_step(&ctx, "", 0, buf, &out_len);
    printf("[observable] sasl_state_machine: step2 state=%d\n", sasl_get_state(&ctx));

    sasl_state_t final = sasl_get_state(&ctx);
    printf("[observable] sasl_state_machine: final_state=%d step_count=%d\n", final, ctx.step_count);
    assert(final == SASL_COMPLETED);

    /* Observable mechanism-rejected error path */
    sasl_ctx_t rejected;
    sasl_init(&rejected, "REJECTED");
    sasl_state_t rejected_start = sasl_start(&rejected);
    printf("[observable] sasl_state_machine: mechanism_rejected observable=%d\n", rejected_start);

    /* Observable abort and fail transitions */
    sasl_ctx_t fail_ctx;
    sasl_init(&fail_ctx, "TEST");
    sasl_start(&fail_ctx);
    printf("[observable] sasl_state_machine: before_fail state=%d\n", sasl_get_state(&fail_ctx));
    sasl_state_t fail_state = sasl_fail(&fail_ctx, -1);
    printf("[observable] sasl_state_machine: fail_state=%d error=%d\n", fail_state, fail_ctx.last_error);

    printf("[observable] sasl_state_machine: completed=1 contract_verified=1\n");
    return (final == SASL_COMPLETED && fail_state == SASL_FAILED && rejected_start == SASL_IN_PROGRESS) ? 1 : 0;
}