/* Real federation handshake state-machine tests, exercising
 * federation_handshake.c with an explicit caller-owned context: valid
 * transitions, rejected transitions observable via returns, state unchanged
 * on rejection, failure/timeout reachability, and NULL safety. */
#include <assert.h>
#include <stddef.h>
#include "federation_handshake.h"

int main(void) {
    handshake_ctx_t c = {0};
    handshake_init(&c);
    assert(handshake_state(&c) == INIT);

    /* INIT -> HANDSHAKE_SENT (local handshake emitted) */
    assert(handshake_send(&c) == 0);
    assert(handshake_state(&c) == HANDSHAKE_SENT);

    /* send while already sent is rejected, state unchanged */
    assert(handshake_send(&c) == -1);
    assert(handshake_state(&c) == HANDSHAKE_SENT);

    /* HANDSHAKE_SENT -> ESTABLISHED (peer acknowledged) */
    assert(handshake_receive(&c) == 0);
    assert(handshake_state(&c) == ESTABLISHED);
    assert(heartbeat_check(&c) == 0); /* linked/live */

    /* ESTABLISHED -> FAILED */
    assert(handshake_fail(&c) == 0);
    assert(handshake_state(&c) == FAILED);

    /* reset -> INIT for retry */
    handshake_reset(&c);
    assert(handshake_state(&c) == INIT);

    /* failure / timeout reachable from HANDSHAKE_SENT */
    assert(handshake_send(&c) == 0);
    assert(handshake_timeout(&c) == 0);
    assert(handshake_state(&c) == TIMED_OUT);

    handshake_reset(&c);
    assert(handshake_state(&c) == INIT);
    assert(handshake_send(&c) == 0);
    assert(handshake_fail(&c) == 0);
    assert(handshake_state(&c) == FAILED);

    /* rejected transitions from INIT */
    handshake_reset(&c);
    assert(handshake_receive(&c) == -1);   /* cannot receive before send */
    assert(handshake_state(&c) == INIT);
    assert(handshake_timeout(&c) == -1);   /* cannot time out from INIT */
    assert(handshake_state(&c) == INIT);
    assert(handshake_fail(&c) == -1);      /* cannot fail before send */
    assert(handshake_state(&c) == INIT);

    /* NULL safety: every entry point must be safe on NULL */
    handshake_init(NULL);
    handshake_reset(NULL);
    assert(handshake_send(NULL) == -1);
    assert(handshake_receive(NULL) == -1);
    assert(handshake_fail(NULL) == -1);
    assert(handshake_timeout(NULL) == -1);
    assert(handshake_state(NULL) == INIT);
    assert(heartbeat_check(NULL) == 1); /* NULL = not linked */

    return 0;
}