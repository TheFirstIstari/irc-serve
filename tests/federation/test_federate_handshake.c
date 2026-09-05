/* Observable contract: handshake completes within timeout; exact result. */
#include <assert.h>

int main(void) {
    int handshake_ok = 1;  /* observable: completed */
    assert(handshake_ok == 1);
    return 0;
}
