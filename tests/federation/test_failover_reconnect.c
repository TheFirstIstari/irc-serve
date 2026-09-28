/* Peer failover / reconnect is NOT implemented by this codebase.
 * Honest CTest skip (return 77) rather than a fabricated reconnect loop.
 * See docs/SPEC_TRACKING.md for this absent feature. */
#include <stdio.h>

int main(void) {
    printf("SKIP: peer failover reconnect is not implemented; no real "
           "implementation exists to test (returning 77).\n");
    return 77;
}