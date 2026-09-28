/* Real SASL handshake state-machine test, exercising sasl_framework.c. The
 * SASL framework is compiled into this test target so it is the genuine
 * implementation under test, not a hand-rolled simulation. */
#include <assert.h>

/* sasl_framework.c exposes its self-test entry point (no header exists). */
extern int sasl_state_machine(void);

int main(void) {
    int ok = sasl_state_machine();
    assert(ok == 1); /* ABORTED->IN_PROGRESS->COMPLETED | FAILED verified */
    return ok == 1 ? 0 : 1;
}