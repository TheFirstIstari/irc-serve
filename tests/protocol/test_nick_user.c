/* Real NICK/USER parser regression tests, exercising protocol_parse.c.
 *
 * Covers: exact command validation, wrong-command rejection, embedded
 * line-break rejection, optional terminal CRLF, missing/extra fields,
 * defined output clearing on error, bounded copies that reject insufficient
 * capacity instead of truncating, and USER realname space preservation. */
#include <assert.h>
#include <string.h>
#include "protocol_parse.h"

int main(void) {
    int tc = -1;
    char nick[32];
    char user[32], host[64], serv[64], real[128];

    /* NICK valid */
    assert(parse_nick("NICK alice", nick, sizeof nick, &tc) == 1);
    assert(strcmp(nick, "alice") == 0);
    assert(tc == 2);

    /* command word is case-insensitive */
    assert(parse_nick("nick bob", nick, sizeof nick, &tc) == 1);
    assert(strcmp(nick, "bob") == 0);

    /* leading whitespace tolerated */
    assert(parse_nick("   NICK carol", nick, sizeof nick, &tc) == 1);
    assert(strcmp(nick, "carol") == 0);

    /* optional terminal CRLF ignored */
    assert(parse_nick("NICK dave\r\n", nick, sizeof nick, &tc) == 1);
    assert(strcmp(nick, "dave") == 0);
    assert(parse_nick("NICK eve\n", nick, sizeof nick, &tc) == 1);
    assert(strcmp(nick, "eve") == 0);

    /* wrong command rejected, output cleared */
    nick[0] = 'X';
    assert(parse_nick("NACK alice", nick, sizeof nick, &tc) == -1);
    assert(nick[0] == '\0');

    /* NULL arguments rejected */
    assert(parse_nick(NULL, nick, sizeof nick, &tc) == -1);
    assert(parse_nick("NICK alice", NULL, sizeof nick, &tc) == -1);
    assert(parse_nick("NICK alice", nick, sizeof nick, NULL) == -1);

    /* empty nickname rejected */
    assert(parse_nick("NICK", nick, sizeof nick, &tc) == -1);
    assert(parse_nick("NICK   ", nick, sizeof nick, &tc) == -1);

    /* extra token = embedded second command, rejected */
    assert(parse_nick("NICK alice bob", nick, sizeof nick, &tc) == -1);

    /* embedded line break rejected */
    assert(parse_nick("NICK ali\nCE bob", nick, sizeof nick, &tc) == -1);
    assert(parse_nick("NICK a\rb", nick, sizeof nick, &tc) == -1);

    /* insufficient capacity rejects (no truncation) */
    assert(parse_nick("NICK alice", nick, 2, &tc) == -1);

    /* USER valid with colon realname */
    assert(parse_user("USER alice host.example server.example :Alice Q. User",
                      user, sizeof user, host, sizeof host, serv, sizeof serv,
                      real, sizeof real, &tc) == 1);
    assert(strcmp(user, "alice") == 0);
    assert(strcmp(host, "host.example") == 0);
    assert(strcmp(serv, "server.example") == 0);
    assert(strcmp(real, "Alice Q. User") == 0);
    assert(tc == 5);

    /* realname with leading ':' has exactly one leading colon stripped */
    assert(parse_user("USER u h s :foo", user, sizeof user, host, sizeof host,
                      serv, sizeof serv, real, sizeof real, &tc) == 1);
    assert(strcmp(real, "foo") == 0);
    assert(parse_user("USER u h s ::foo", user, sizeof user, host, sizeof host,
                      serv, sizeof serv, real, sizeof real, &tc) == 1);
    assert(strcmp(real, ":foo") == 0);

    /* realname trailing + interior spaces preserved verbatim */
    assert(parse_user("USER u h s bar  ", user, sizeof user, host, sizeof host,
                      serv, sizeof serv, real, sizeof real, &tc) == 1);
    assert(strcmp(real, "bar  ") == 0); /* preserved trailing spaces */
    assert(parse_user("USER u h s :a  b", user, sizeof user, host, sizeof host,
                      serv, sizeof serv, real, sizeof real, &tc) == 1);
    assert(strcmp(real, "a  b") == 0);  /* preserved interior double space */

    /* terminal CRLF accepted on USER */
    assert(parse_user("USER u h s z\r\n", user, sizeof user, host, sizeof host,
                      serv, sizeof serv, real, sizeof real, &tc) == 1);
    assert(strcmp(real, "z") == 0);

    /* wrong command, output cleared */
    user[0] = 'X';
    assert(parse_user("USED u h s :r", user, sizeof user, host, sizeof host,
                      serv, sizeof serv, real, sizeof real, &tc) == -1);
    assert(user[0] == '\0');

    /* missing field / empty realname rejected */
    assert(parse_user("USER u h", user, sizeof user, host, sizeof host,
                      serv, sizeof serv, real, sizeof real, &tc) == -1);
    assert(parse_user("USER u h s  ", user, sizeof user, host, sizeof host,
                      serv, sizeof serv, real, sizeof real, &tc) == -1);
    assert(parse_user("USER u h s :", user, sizeof user, host, sizeof host,
                      serv, sizeof serv, real, sizeof real, &tc) == -1);

    /* embedded line break rejected */
    assert(parse_user("USER u h s :x\nY", user, sizeof user, host, sizeof host,
                      serv, sizeof serv, real, sizeof real, &tc) == -1);

    /* NULL arguments rejected */
    assert(parse_user(NULL, user, sizeof user, host, sizeof host,
                      serv, sizeof serv, real, sizeof real, &tc) == -1);

    /* insufficient capacity rejects without truncation */
    assert(parse_user("USER u h s :realname", user, sizeof user, host, sizeof host,
                      serv, sizeof serv, real, 2, &tc) == -1);
    assert(parse_user("USER u h s :realname", user, 1, host, sizeof host,
                      serv, sizeof serv, real, sizeof real, &tc) == -1);

    return 0;
}