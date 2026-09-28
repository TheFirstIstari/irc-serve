/* Peer discovery (advertise / graceful leave) is NOT implemented by this
 * codebase. Honest CTest skip (return 77) rather than hand-rolled stubs.
 * See docs/SPEC_TRACKING.md for this absent feature. */
#include <stdio.h>

int main(void) {
    printf("SKIP: load-balancer peer discovery is not implemented; no real "
           "implementation exists to test (returning 77).\n");
    return 77;
}
