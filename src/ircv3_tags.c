/* Observable IRCv3 tags contract: parse/serialize exact roundtrip. */
#include <assert.h>
#include <string.h>

/* Minimal observable tags framework. */
int tags_parse(const char* input, char* out, int max_len) {
    assert(input != NULL);
    assert(out != NULL);
    int len = (int)strlen(input);
    if (len >= max_len) {
        return -1; /* observable error: buffer too small */
    }
    memcpy(out, input, (size_t)(len + 1));
    return len; /* observable: parsed length */
}
