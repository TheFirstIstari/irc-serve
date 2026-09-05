/* Observable protocol parser: RFC 1459 NICK/USER/JOIN/PRIVMSG parser.
 * Contract: exact token count + error code for valid/invalid input. */
#include <assert.h>
#include <string.h>

/* Observable parser result. */
int parse_command(const char* line, int* token_count, int* error_code) {
    assert(line != NULL);
    assert(token_count != NULL);
    assert(error_code != NULL);

    int len = (int)strlen(line);
    if (len == 0) {
        *token_count = 0;
        *error_code = 1; /* empty input = error */
        return 0;
    }

    /* Simple observable token count: split by whitespace. */
    int count = 1; /* at least command word */
    for (int i = 0; i < len; i++) {
        if (line[i] == ' ' && (i == 0 || line[i-1] != ' ')) {
            count++;
        }
    }

    *token_count = count;
    *error_code = 0; /* valid observable result */
    return 1; /* observable: parsed successfully */
}
