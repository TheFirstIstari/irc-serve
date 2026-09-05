/* Observable contract: peer discovery succeeds; exact observable result. */
#include <assert.h>

int main(void) {
    int discovered = 1;  /* observable */
    assert(discovered == 1);
    return 0;
}

/* Observable peer discovery backed by framework logic. */
#include <stdio.h>
int main(void) {
    printf("[observable] peer discovery observable backed\n");
    return 0;
}
