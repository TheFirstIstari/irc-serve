/* Real IRCv3 tag validate-and-copy roundtrip test, exercising ircv3_tags.c:
 * tags_parse() then tags_serialize() must reproduce the input byte-for-byte,
 * including '=' in values and empty values. */
#include <assert.h>
#include <string.h>
#include "ircv3_tags.h"

static void check_roundtrip(const char* input) {
    char parsed[128];
    char out[128];
    int prc = tags_parse(input, parsed, (int)sizeof parsed);
    assert(prc == (int)strlen(input));
    assert(strcmp(parsed, input) == 0);
    int src = tags_serialize(parsed, out, (int)sizeof out);
    assert(src == (int)strlen(parsed));
    assert(strcmp(out, parsed) == 0);
    assert(strcmp(out, input) == 0);
}

int main(void) {
    check_roundtrip("@label=123;key=val");
    check_roundtrip("@key=value");
    check_roundtrip("@a=b=c;d=1");
    check_roundtrip("@empty=");
    check_roundtrip("plain");
    check_roundtrip("@x=-1.5;y=+2");
    check_roundtrip("@a=b=c=d");
    return 0;
}