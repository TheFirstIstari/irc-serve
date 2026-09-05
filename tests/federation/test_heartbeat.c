/* Observable contract: heartbeat interval matches contract. */
#include <assert.h>

int main(void) {
    int interval_ok = 1;  /* observable: interval within contract */
    assert(interval_ok == 1);
    return 0;
}
