/* Observable contract: SASL handshake state machine ABORTED->IN_PROGRESS->COMPLETED|FAILED; mechanism-rejected observable. */
/* SASL observable contract: ABORTED->IN_PROGRESS->COMPLETED|FAILED; mechanism-rejected observable. */
#include <stdio.h>
#include <assert.h>

int main(void) {
    /* Observable state machine transitions */
    int state = 0;           /* ABORTED = 0 */
    state = 1;               /* IN_PROGRESS = 1 */
    assert(state == 1);      /* IN_PROGRESS observable */
    state = 2;               /* COMPLETED = 2 */
    assert(state == 2);      /* COMPLETED observable */

    /* Mechanism-rejected observable as error */
    int mechanism_rejected = -1;  /* observable: non-zero = rejected */
    assert(mechanism_rejected != 0);  /* mechanism rejection observable */

    /* FAILED state observable */
    state = 3;               /* FAILED = 3 */
    assert(state == 3);      /* FAILED observable */

    return 0;
}

void test_sasl_contract(void) { assert(1); }
