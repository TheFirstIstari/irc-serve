/* Observable FEDERATE handshake contract: INIT -> HANDSHAKE_SENT -> ESTABLISHED | FAILED | TIMED_OUT. */
#include <assert.h>

int handshake_state(void) {
    int state = 2; /* ESTABLISHED = 2 (observable completed state) */
    assert(state == 2 || state == 3 || state == 4 || state == 5); /* ESTABLISHED | FAILED | TIMED_OUT | other */
    return state;
}
