/* IRCv3 CAP negotiation is NOT implemented by this codebase.
 * Honest CTest skip (return 77) rather than fabricated hand-rolled
 * "observable" logic. See docs/SPEC_TRACKING.md for this absent feature. */
#include <stdio.h>

int main(void) {
    printf("SKIP: CAP negotiation (LS/REQ/ACK/NAK) is not implemented; no "
           "real implementation exists to test (returning 77).\n");
    return 77;
}