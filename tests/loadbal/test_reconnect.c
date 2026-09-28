/* Client reconnect preserving session state is NOT implemented by this
 * codebase. Honest CTest skip (return 77) rather than simulated reconnect
 * state. See docs/SPEC_TRACKING.md for this absent feature. */
#include <stdio.h>

int main(void) {
    printf("SKIP: client reconnect is not implemented; no real implementation "
           "exists to test (returning 77).\n");
    return 77;
}