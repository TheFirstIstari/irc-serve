/* Real heartbeat liveness test, exercising federation_handshake.c: heartbeat
 * reports live only once the handshake reaches ESTABLISHED, and otherwise
 * reports not-linked. NULL context reports not-linked. */
#include <assert.h>
#include <stddef.h>
#include "federation_handshake.h"

int main(void) {
    handshake_ctx_t c = {0};
    handshake_init(&c);

    assert(heartbeat_check(&c) != 0);            /* INIT: not linked */
    assert(handshake_send(&c) == 0);
    assert(heartbeat_check(&c) != 0);            /* HANDSHAKE_SENT: not linked */
    assert(handshake_receive(&c) == 0);
    assert(heartbeat_check(&c) == 0);            /* ESTABLISHED: linked */
    assert(handshake_fail(&c) == 0);
    assert(heartbeat_check(&c) != 0);            /* FAILED: not linked */

    assert(heartbeat_check(NULL) != 0);          /* NULL: not linked */
    return 0;
}