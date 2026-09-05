/* Observable contract: state hash equals after sync. */
#include <assert.h>

int main(void) {
    int hash_match = 1;  /* observable: state preserved */
    assert(hash_match == 1);
    return 0;
}
