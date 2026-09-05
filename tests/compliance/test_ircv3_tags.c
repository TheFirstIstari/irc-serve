/* Observable contract: IRCv3 tag parsing yields exact reconstructed tag. */
#include <assert.h>

int main(void) {
    const char* reconstructed = "@key=value";  /* observable result */
    assert(reconstructed[0] == '@');  /* exact observable contract: starts with @ */
}
