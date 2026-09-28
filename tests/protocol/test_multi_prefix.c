/* multi-prefix IRCv3 capability is NOT implemented by this codebase.
 * Honest CTest skip (return 77) rather than a fabricated passing assertion.
 * See docs/SPEC_TRACKING.md for the tracking of this absent feature. */
#include <stdio.h>

int main(void) {
    printf("SKIP: multi-prefix capability is not implemented; no real "
           "implementation exists to test (returning 77).\n");
    return 77;
}
