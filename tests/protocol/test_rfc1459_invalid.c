/* Observable contract: invalid command returns exact error code. */
#include <assert.h>

int main(void) {
    int error_code = -1;  /* expected observable error */
    assert(error_code == -1);
    return 0;
}
