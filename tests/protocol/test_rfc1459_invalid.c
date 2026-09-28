/* Real NICK/USER invalid-input regression tests, exercising protocol_parse.c.
 * Complements test_nick_user by centring on rejection paths: each returns -1
 * and leaves a defined (cleared) output state. */
#include <assert.h>
#include <string.h>
#include "protocol_parse.h"

#define BIG 128

int main(void) {
    int tc = -1;
    char nick[BIG];
    char user[BIG], host[BIG], serv[BIG], real[BIG];

    /* wrong command for each parser */
    assert(parse_nick("PRIVMSG #c hi", nick, sizeof nick, &tc) == -1);
    assert(parse_nick("USER x y z :r", nick, sizeof nick, &tc) == -1);
    assert(parse_user("NICK alice", user, sizeof user, host, sizeof host,
                      serv, sizeof serv, real, sizeof real, &tc) == -1);

    /* NULL buffer / capacity rejection */
    assert(parse_nick("NICK a", nick, 0, &tc) == -1);
    assert(parse_nick("NICK a", nick, -1, &tc) == -1);
    assert(parse_user("USER u h s :r", user, sizeof user, host, sizeof host,
                      serv, -1, real, sizeof real, &tc) == -1);

    /* embedded newline (multi-line / multiple commands) */
    assert(parse_nick("NICK\nalice", nick, sizeof nick, &tc) == -1);
    assert(parse_nick("NICK a\nNICK b", nick, sizeof nick, &tc) == -1);
    assert(parse_user("USER u h s :a\nb", user, sizeof user, host, sizeof host,
                      serv, sizeof serv, real, sizeof real, &tc) == -1);

    /* extra whitespace-separated tokens after NICK = extra command */
    assert(parse_nick("NICK a b c", nick, sizeof nick, &tc) == -1);

    /* insufficient capacity rejects (no silent truncation) */
    assert(parse_nick("NICK abcdef", nick, 3, &tc) == -1);
    assert(parse_user("USER abcdef h s :r", user, 3, host, sizeof host,
                      serv, sizeof serv, real, sizeof real, &tc) == -1);

    /* on rejection the outputs are cleared */
    nick[0] = 'Q';
    assert(parse_nick("BOGUS x", nick, sizeof nick, &tc) == -1);
    assert(nick[0] == '\0');
    assert(tc == 0);

    real[0] = 'Q';
    assert(parse_user("USER u h s", user, sizeof user, host, sizeof host,
                      serv, sizeof serv, real, sizeof real, &tc) == -1);
    assert(real[0] == '\0');

    return 0;
}