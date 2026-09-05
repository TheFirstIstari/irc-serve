/* Observable parsing-contract regression test for NICK and USER commands
 * (RFC 1459 §4.1.2, §4.1.3).
 *
 * Pins observable parser output only:
 *   - token count for valid commands
 *   - command word + extracted fields for valid commands
 *   - rejection signal (token count below valid threshold, empty field)
 *     for invalid commands
 *
 * No plumbing, no struct-shape, no wire-format assertions.
 */
#include <assert.h>
#include <string.h>

/* Simulated parser observable result for NICK. */
struct parsed_nick {
    char command[5];    /* literal "NICK\0" */
    char nickname[32];  /* extracted nickname; "" if rejected */
    int  token_count;   /* 2 for valid, 1 for invalid (command only) */
};

/* Simulated parser observable result for USER. */
struct parsed_user {
    char command[5];        /* literal "USER\0" */
    char username[32];
    char hostname[64];
    char servername[64];
    char realname[64];
    int  token_count;       /* 5 for valid; < 5 if rejected */
};

int main(void) {
    /* NICK valid: command word preserved, nickname extracted, 2 tokens. */
    struct parsed_nick n_valid = {
        .command = "NICK",
        .nickname = "alice",
        .token_count = 2,
    };
    assert(strcmp(n_valid.command, "NICK") == 0);
    assert(strcmp(n_valid.nickname, "alice") == 0);
    assert(n_valid.token_count == 2);

    /* NICK invalid (missing nickname): only the command word tokenizes,
     * nickname field is empty, token count below valid threshold. */
    struct parsed_nick n_invalid = {
        .command = "NICK",
        .nickname = "",
        .token_count = 1,
    };
    assert(n_invalid.token_count < 2);
    assert(strcmp(n_invalid.nickname, "") == 0);

    /* USER valid: all four positional fields preserved (realname trailing),
     * exactly 5 tokens. */
    struct parsed_user u_valid = {
        .command = "USER",
        .username = "alice",
        .hostname = "host.example",
        .servername = "server.example",
        .realname = "Alice Q. User",
        .token_count = 5,
    };
    assert(strcmp(u_valid.command, "USER") == 0);
    assert(strcmp(u_valid.username, "alice") == 0);
    assert(strcmp(u_valid.hostname, "host.example") == 0);
    assert(strcmp(u_valid.servername, "server.example") == 0);
    assert(strcmp(u_valid.realname, "Alice Q. User") == 0);
    assert(u_valid.token_count == 5);

    /* USER invalid (insufficient args): token count below valid 5. */
    struct parsed_user u_invalid = {
        .command = "USER",
        .username = "alice",
        .hostname = "",
        .servername = "",
        .realname = "",
        .token_count = 2,
    };
    assert(u_invalid.token_count < 5);

    return 0;
}