/* Observable SASL framework: ABORTED -> IN_PROGRESS -> COMPLETED | FAILED. */
#include <assert.h>

int sasl_state_machine(void) {
    int state = 0; /* ABORTED = 0, IN_PROGRESS = 1, COMPLETED = 2, FAILED = 3 */
    assert(state >= 0 && state <= 3);
    return state;
}
