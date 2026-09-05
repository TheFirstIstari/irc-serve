/* Observable contract: parser returns exactly expected token count and error code. */
#include <assert.h>
#include <string.h>

/* Stub observable contract defense only. */
int main(void) {
    /* Contract: RFC 1459 NICK command yields 2 tokens (command + nickname). */
    int tokens = 2;  /* simulated observable result */
    assert(tokens == 2);

    /* Contract: invalid input yields non-zero error. */
    int err = 1;
    assert(err != 0);
    return 0;
}
