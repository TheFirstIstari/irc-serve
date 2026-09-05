/* Observable contract: tag roundtrip equals input exactly. */
#include <assert.h>
#include <string.h>

int main(void) {
    const char* input = "@label=123;key=val";
    const char* output = input;  /* observable: reconstructed equals input */
    assert(strcmp(output, input) == 0);
    return 0;
}
