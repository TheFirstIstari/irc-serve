/* Real SASL handshake state-machine test, exercising sasl_framework.c. The
 * SASL framework is part of irc_core (#86), so this is the genuine
 * implementation under test and not a hand-rolled simulation.
 *
 * It includes src/sasl_framework.h rather than declaring sasl_state_machine()
 * itself, which is what this file used to do on the stated grounds that no
 * header existed. One does: sasl_framework.h has declared all seven entry
 * points for some time, and the hand-written extern declaration here was a
 * second copy of a prototype that had drifted far enough to be worth trusting
 * over the real one. */
#include <assert.h>

#include "sasl_framework.h"

int main(void) {
    int ok = sasl_state_machine();
    assert(ok == 1); /* ABORTED->IN_PROGRESS->COMPLETED | FAILED verified */
    return ok == 1 ? 0 : 1;
}
