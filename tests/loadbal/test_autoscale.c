/* Load-balancer auto-scaling is NOT implemented by this codebase. Honest
 * CTest skip (return 77) rather than fabricated node lifecycle / "RSS" claims.
 * See docs/SPEC_TRACKING.md for this absent feature. */
#include <stdio.h>

int main(void) {
    printf("SKIP: auto-scaling (spawn/shutdown/propagation) is not "
           "implemented; no real implementation exists to test (returning 77).\n");
    return 77;
}