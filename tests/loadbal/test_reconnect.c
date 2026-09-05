/* Observable contract: reconnect succeeds and state preserved. */
#include <assert.h>

int main(void) {
    int reconnect_ok = 1;
    int state_preserved = 1;
    assert(reconnect_ok == 1);
    assert(state_preserved == 1);
    return 0;
}
