/* Real parse_command() regression tests (RFC 1459 tokenisation), exercising
 * protocol_parse.c. Pins the 0-success / -1-error contract and token counts. */
#include <assert.h>
#include <stddef.h>
#include "protocol_parse.h"

int main(void) {
    int tc = -1;
    int ec = -1;

    /* single token */
    assert(parse_command("PING", &tc, &ec) == 0);
    assert(tc == 1);
    assert(ec == 0);

    /* multiple whitespace-separated tokens (interior spaces joined) */
    assert(parse_command("PRIVMSG #chan Hello there", &tc, &ec) == 0);
    assert(tc == 4);
    assert(ec == 0);

    assert(parse_command("JOIN #general", &tc, &ec) == 0);
    assert(tc == 2);

    /* empty line has zero tokens */
    assert(parse_command("", &tc, &ec) == 0);
    assert(tc == 0);

    /* leading / trailing whitespace does not add tokens */
    assert(parse_command("   NICK alice   ", &tc, &ec) == 0);
    assert(tc == 2);

    /* CR / LF count as whitespace separators */
    assert(parse_command("NICK a\r\nNICK b", &tc, &ec) == 0);
    assert(tc == 4);

    /* NULL argument -> error, outputs defined */
    tc = -1; ec = -1;
    assert(parse_command(NULL, &tc, &ec) == -1);
    assert(tc == 0);
    assert(ec != 0);

    return 0;
}