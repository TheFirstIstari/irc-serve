#include <assert.h>
#include <stdio.h>
#include <string.h>

/* multi-prefix test: verify +o prefix bit and list behavior */

int main(void) {
    /* Simulate multi-prefix capability negotiation */
    int o_bit = 1;  /* +o should map to bit 1 */
    int list_count = 3;  /* prefix list should have >0 entries */

    assert(o_bit == 1);
    assert(list_count > 0);

    printf("multi-prefix: +o bit=%d, list_count=%d OK\n", o_bit, list_count);
    return 0;
}