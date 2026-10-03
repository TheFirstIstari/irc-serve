/* test_numeric_arity.c -- 461's `<command>` field, asserted POSITIONALLY, and
 * the numerics that must NOT grow one.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS FILE EXISTS WHEN SEVENTEEN OTHER ASSERTIONS ALREADY PIN 461's BYTES
 * ---------------------------------------------------------------------------
 * Every other needle in the suite that mentions 461 names a line the node happens
 * to send. That is enough to catch a REGRESSION and not enough to catch the defect
 * this file is about, and the reason is structural rather than accidental:
 *
 *   - A needle of `:irc.test 461 alice :Not enough parameters\r\n` passes against
 *     a node that omits RFC 2812 5.2's `<command>` field entirely, because the
 *     field it is missing is a field the needle does not have.
 *   - A needle of `:irc.test 461 alice PRIVMSG :Not enough parameters\r\n` passes
 *     against a node that HARDCODED "PRIVMSG", which is the same defect wearing a
 *     hat. Only a second, different verb catches it.
 *
 * So this file does two things no other assertion here does. It PARSES the 461
 * line into fields and asserts the verb is the SECOND one, so the assertion is
 * about the field list and not about a substring; and it drives the SAME check
 * through twenty-two probes over seventeen verbs, so "the field is present" and
 * "the field is the right verb" are separate failures with separate messages.
 *
 * RFC 2812 5.2, the whole of the claim:
 *
 *     461 ERR_NEEDMOREPARAMS  "<client> <command> :Not enough parameters"
 *     451 ERR_NOTREGISTERED   "<client> :You have not registered"
 *     482 ERR_CHANOPRIVSNEEDED "<client> <channel> :You're not channel operator"
 *
 * 451 has NO field before the text and 482's is a CHANNEL that the caller already
 * passes. Both are asserted here as having exactly the field list the RFC gives
 * them, which is what makes "only 461 gained a command word" a checked statement
 * rather than a hopeful one. A rule of "every refusal names the verb" would give
 * 451 a field it does not have and would replace 482's channel with a verb, and
 * both faults would pass every 461 needle in the suite.
 *
 * ---------------------------------------------------------------------------
 * THE STANDARD-REPLIES HALF, AND WHY IT IS HERE RATHER THAN LEFT TO
 * test_standard_replies.c
 * ---------------------------------------------------------------------------
 * The field is added on the LEGACY branch only. A `FAIL` already carries the
 * command word as its own required `<command>`, so a fix that also prepended it
 * there would render
 *
 *     FAIL PRIVMSG PRIVMSG NEED_MORE_PARAMS :Not enough parameters
 *
 * and put the verb where a client reads `<context>`. That is a field-count fault
 * on the branch whose field count is defined by a DIFFERENT specification, and
 * asserting only the legacy half would not see it -- so the paired client is
 * checked here too, and the verb must appear EXACTLY ONCE.
 *
 * NO sleep() ANYWHERE (6.3): every wait is tc_expect()'s select()-driven deadline
 * and every window is closed by a numbered PING's PONG, because tc_expect()
 * searches the ACCUMULATED buffer and a reused token would be satisfied by an
 * earlier PONG with no read at all.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

#define T_IO_MS 15000
#define T_READY_MS 15000

/* The fixture's nodes answer with this. Every expectation below is a whole line
 * and the server name is the first field of all of them, so it is written out
 * rather than assembled -- an assembled name would follow whatever the node
 * called itself and notice nothing. */
#define BIN_NAME "irc.test"

/* The channel the too-MANY probes name. It does not have to exist: every arity
 * check in this node runs BEFORE the channel is resolved -- which is what
 * handle_mode()'s comment about "the 482 and 472 refusals below come first in the
 * RFC order" is about -- so a probe is answered 461 whether or not the channel is
 * real. Naming a real one anyway would make the assertion depend on that ordering
 * holding, which is a different claim from the one this file makes. */
#define ARITY_CHAN "#ARITY"

/* A field as the wire carries it. RFC 1459 2.3: a parameter that begins with ':'
 * is the trailing one, and everything before it is separated by a single space.
 * These bounds are the message's own, not a guess about line length: a reply is
 * short, and a field longer than this could not have been rendered. */
#define ARITY_MAX_FIELD 160

/* One wrong-arity probe: the line to send, and the verb RFC 2812 5.2 requires the
 * answer to name. The verb is written out rather than derived from the line so
 * that a handler answering the wrong verb fails the test rather than agreeing
 * with it. */
typedef struct {
    const char *send;
    const char *verb;
    const char *why; /* what a reader of the failure is looking at */
} arity_case_t;

/* TWENTY-THREE PROBES ACROSS SEVENTEEN VERBS, ordered so the ones with the fewest
 * side effects come first. Nothing here registers a second connection, joins a
 * channel, or sets state: every case is a refusal that happens before the handler
 * does anything, which is what keeps the cases independent of each other and of
 * their order under `ctest -j`.
 *
 * FIVE VERBS APPEAR TWICE, once for the TOO FEW direction and once for the TOO MANY
 * direction, because 461's own text reads "Not enough parameters" either way -- the
 * ambiguity docs/RFC2812_CONFORMANCE.md section 5 records -- so both directions
 * are driven rather than the convenient one.
 *
 * PASS, BATCH, OPER, SERVICE, REHASH, KILL and WHO are deliberately NOT here. PASS
 * and BATCH have state; OPER, SERVICE, REHASH and KILL have no handler or a NULL
 * one and answer 421, so a probe against them would be testing the dispatch table
 * rather than the arity; and bare WHO is not a refusal at all -- this node gives it
 * the de-facto '*' mask and answers 352, which is the right answer and not this
 * file's subject.
 *
 * USERHOST, ISON, JOIN and PART appear ONCE rather than twice, for two reasons
 * worth writing down because both were found by trying the probe and reading the
 * wire rather than by reading the handler:
 *
 *   - USERHOST and ISON take a MASK LIST, so `nparams < 1` is the only arity they
 *     have. `USERHOST a b` is a well-formed question about two masks and is
 *     answered 302/304, not 461.
 *   - JOIN and PART take a COMMA-SEPARATED CHANNEL LIST in their first parameter
 *     and have no upper bound at all, so `JOIN #A #B` is well-formed (the second
 *     parameter is ignored) and `PART #c x y` carries a part reason. Neither has a
 *     too-MANY direction to drive, which is a fact about this node's handlers and
 *     not about RFC 2812. */
static const arity_case_t k_arity[] = {
    /* TOO FEW or TOO MANY, and the `why` says which -- because 461's own text
     * reads "Not enough parameters" in BOTH directions, so the number cannot tell
     * them apart and only the command word says which command it was. */
    { "NICK a b"                   , "NICK",    "a space in a nickname is two -- too MANY" },
    { "USERHOST"                   , "USERHOST", "the mask is mandatory -- too FEW" },
    { "JOIN"                       , "JOIN",    "no channel named -- too FEW" },
    { "PART"                       , "PART",    "no channel named -- too FEW" },
    { "TOPIC"                      , "TOPIC",   "no channel named -- too FEW" },
    { "KICK"                       , "KICK",    "no channel named -- too FEW" },
    { "MODE"                       , "MODE",    "no channel named -- too FEW" },
    { "INVITE"                     , "INVITE",  "no channel and no nickname -- too FEW" },
    { "KNOCK"                      , "KNOCK",   "no channel named -- too FEW" },
    { "ISON"                       , "ISON",    "the mask is mandatory -- too FEW" },
    { "PRIVMSG"                    , "PRIVMSG", "no target and no text -- too FEW" },
    { "NOTICE"                     , "NOTICE",  "no target and no text -- too FEW" },
    { "SETNAME"                    , "SETNAME", "the realname is mandatory -- too FEW" },
    { "CHOPER"                     , "CHOPER",  "no target and no password -- too FEW" },
    { "WHOIS a b"                  , "WHOIS",   "exactly one nickname -- too MANY" },
    { "AWAY one two"               , "AWAY",    "one message, not two -- too MANY" },
    { "SETNAME x y"                , "SETNAME", "exactly one realname -- too MANY" },
    { "CHOPER alice"               , "CHOPER",  "a target and a password -- too FEW" },
    { "ADMIN " BIN_NAME " x"       , "ADMIN",   "at most one mask -- too MANY" },
    { "TOPIC " ARITY_CHAN " x y"   , "TOPIC",   "at most a channel and a topic -- too MANY" },
    { "KICK " ARITY_CHAN " a b c"  , "KICK",    "at most a channel, a nick, a comment -- too MANY" },
    { "MODE " ARITY_CHAN " +k a b" , "MODE",    "at most a channel, modes, one argument -- too MANY" },
};

/* Join ARITY_CHAN and wait for the end of the JOIN sequence.
 *
 * ONE CHANNEL, JOINED BEFORE THE SWEEP, and the reason is a single handler
 * ordering: handle_mode() checks `nparams > 3` -- its too-MANY 461 -- AFTER
 * resolve_joined(), while every other handler checks arity first. So
 * `MODE #ARITY +k a b` is answered 403 on a channel that does not exist and 461 on
 * one that does. Joining first makes the sweep test what it claims to test (the
 * arity field) rather than which of the two refusals comes first.
 *
 * It is still not load-bearing for the other twenty-one probes, and that is
 * asserted by ARITY_CHAN's own comment rather than left to be discovered. */
static void join_arity_channel(test_client_t *c)
{
    TF_CHECK_MSG(tc_send(c, "JOIN " ARITY_CHAN) == 0, "JOIN send failed");
    TF_CHECK_MSG(tc_expect(c, ":" BIN_NAME " 366 alice " ARITY_CHAN " ", T_IO_MS) == 0,
                 "alice never joined " ARITY_CHAN);
    TF_CHECK_MSG(tc_send(c, "PING :post-join") == 0, "post-join PING send failed");
    TF_CHECK_MSG(tc_expect(c, "post-join", T_IO_MS) == 0, "no post-join PONG");
}

/* Join a channel somebody else created, which is the only way to be a member
 * without the creator's +o. See check_482_keeps_its_channel() for why the 482 check
 * needs that. */
static void join_existing_channel(test_client_t *c, const char *nick)
{
    char needle[128];

    TF_CHECK_MSG(tc_send(c, "JOIN " ARITY_CHAN) == 0, "JOIN send failed");
    (void)snprintf(needle, sizeof needle, ":" BIN_NAME " 366 %s " ARITY_CHAN " ",
                   nick);
    TF_CHECK_MSG(tc_expect(c, needle, T_IO_MS) == 0,
                 "%s never joined " ARITY_CHAN ", so the 482 check below would be "
                 "about a client that is not on the channel at all", nick);
    TF_CHECK_MSG(tc_send(c, "PING :post-join") == 0, "post-join PING send failed");
    TF_CHECK_MSG(tc_expect(c, "post-join", T_IO_MS) == 0, "no post-join PONG");
}

static unsigned g_drain_seq;

/* Numbered because tc_expect() searches the ACCUMULATED buffer: a reused token
 * would be satisfied by an earlier PONG without a single read, and every window
 * below would then be measuring the read schedule rather than the wire. */
static size_t mark(test_client_t *c)
{
    /* `line` is sized for `"PING :"` plus a 64-byte token plus the terminator, not
     * for `"PING :"` plus a 64-byte token: gcc-16's -Wformat-truncation reads the
     * declared bound of the token buffer rather than its length, so a 64-byte
     * `line` needs 71 and is refused at any size below it. */
    char line[128];
    char token[64];
    char needle[160];
    const char *at;

    (void)snprintf(token, sizeof token, "arity-m%u", g_drain_seq++);
    (void)snprintf(line, sizeof line, "PING :%s", token);
    TF_CHECK_MSG(tc_send(c, line) == 0, "mark PING send failed");
    TF_CHECK_MSG(tc_expect(c, token, T_IO_MS) == 0, "no PONG for mark %s", line);
    (void)snprintf(needle, sizeof needle, "PONG %s %s\r\n", BIN_NAME, token);
    at = strstr(tc_buffer(c), needle);
    TF_CHECK_MSG(at != NULL,
                 "the mark PONG \"%s\" vanished from the buffer, so every window "
                 "below would be measured against the wrong offset", needle);
    return (at != NULL) ? (size_t)(at - tc_buffer(c)) : 0u;
}

static void register_client(test_client_t *c, int port, const char *nick,
                            const char *caps)
{
    char line[256];

    TF_CHECK_MSG(tc_connect(c, port) == 0, "%s could not connect", nick);
    if (caps != NULL) {
        (void)snprintf(line, sizeof line, "CAP REQ :%s", caps);
        TF_CHECK_MSG(tc_send(c, line) == 0, "%s CAP REQ send failed", nick);
        (void)snprintf(line, sizeof line, " ACK :%s\r\n", caps);
        TF_CHECK_MSG(tc_expect(c, line, T_IO_MS) == 0,
                     "%s was not ACKed \"%s\", so the node does not have the "
                     "capability and the assertions about it would be about a "
                     "client that never negotiated anything", nick, caps);
    }
    (void)snprintf(line, sizeof line, "NICK %s", nick);
    TF_CHECK_MSG(tc_send(c, line) == 0, "%s NICK send failed", nick);
    (void)snprintf(line, sizeof line, "USER %s 0 *spoofed.example :Real %s", nick,
                   nick);
    TF_CHECK_MSG(tc_send(c, line) == 0, "%s USER send failed", nick);
    if (caps != NULL) {
        TF_CHECK_MSG(tc_send(c, "CAP END") == 0, "%s CAP END send failed", nick);
    }
    TF_CHECK_MSG(tc_expect(c, " 001 ", T_IO_MS) == 0, "%s never registered", nick);
}

/* The first CRLF-terminated line in `buf` that begins `:irc.test 461 `, copied to
 * `out`. Returns 0 on success, -1 when the window holds no such line.
 *
 * The PREFIX is matched rather than any occurrence of "461" because a 461 in the
 * trailing text of some other numeric is not a 461 -- and because a needle that
 * matched a suffix of a longer line would pass a node that never sent the line. */
static int find_461(const char *buf, size_t from, char *out, size_t out_cap)
{
    const char *at = buf + from;
    const char *stop;

    while (*at != '\0') {
        stop = strstr(at, "\r\n");
        if (stop == NULL) {
            return -1;
        }
        if (strncmp(at, ":" BIN_NAME " 461 ", sizeof(":" BIN_NAME " 461 ") - 1) == 0) {
            size_t len = (size_t)(stop - at);

            if (len + 1u > out_cap) {
                return -1;
            }
            memcpy(out, at, len);
            out[len] = '\0';
            return 0;
        }
        at = stop + 2;
    }
    return -1;
}

/* Split a wire line into its RFC 1459 2.3 fields.
 *
 * The prefix is stripped first, and that is not tidiness: every one of these lines
 * begins `:irc.test`, so a splitter that looked for the first ':' would find the
 * PREFIX's and call the whole line one trailing parameter. The trailing parameter
 * is the first field that BEGINS with a colon -- i.e. a colon at the start of the
 * line or immediately after a space -- which is the rule 2.3 states and the only
 * one that survives a prefix, a nickmask, and a mode string that may itself hold
 * a colon.
 *
 * The trailing parameter is kept whole, colon included, so an assertion about it is
 * about the text rather than about its first word.
 *
 * Returns the field count, or -1 when the line has no trailing parameter, which is
 * itself a fault: every numeric this file checks ends in one. */
static int split_line(const char *line, char fields[][ARITY_MAX_FIELD], int max)
{
    const char *p = line;
    const char *param;
    int n = 0;

    if (*p == ':') {
        const char *sp = strchr(p, ' ');

        if (sp == NULL) {
            return -1;
        }
        p = sp + 1;
    }
    while (*p != '\0' && n < max) {
        size_t len;

        if (*p == ':') {
            len = strlen(p);
        } else {
            const char *sp = strchr(p, ' ');

            len = (sp != NULL) ? (size_t)(sp - p) : strlen(p);
        }
        if (len >= ARITY_MAX_FIELD) {
            return -1;
        }
        memcpy(fields[n], p, len);
        fields[n][len] = '\0';
        n++;
        param = (*p == ':') ? NULL : strchr(p, ' ');
        if (param == NULL) {
            break;
        }
        p = param + 1;
    }
    /* n == max means the line had more fields than the caller's array, which is a
     * fault in the caller rather than a long line, and is reported the same way. */
    return (n >= max) ? -1 : n;
}

/* The `461` field list, parsed. `line` is expected to be exactly
 * `:<server> 461 <client> <command> :<text>` -- four wire fields, or three
 * parameters plus the trailing one -- and this asserts each of them by position.
 *
 * THE POSITIONAL ASSERTION IS THE POINT. The suite's other 461 needles match the
 * bytes; this one decomposes them. A node that omitted <command> produces three
 * fields and fails on the count with a message that says so, rather than passing
 * a needle that had no room for the field. */
static void expect_461_fields(const char *line, const char *who,
                              const char *client, const char *verb)
{
    char fields[8][ARITY_MAX_FIELD];
    int n = split_line(line, fields, 8);

    TF_CHECK_MSG(n >= 0,
                 "%s: 461 has no trailing parameter, so the line is not an IRC "
                 "message at all: \"%s\"", who, line);
    if (n < 0) {
        return;
    }
    /* prefix, numeric, client, command, text. */
    /* The prefix is stripped by split_line(), so these are PARAMETERS: 461,
     * <client>, <command>, :<text>. Four is the RFC's field list; three means
     * <command> is absent and five means something was added to it. */
    TF_CHECK_MSG(n == 4,
                 "%s: expected 4 parameters (461, <client>, <command>, :<text>) and "
                 "got %d. RFC 2812 5.2 gives 461 the field list \"<client> "
                 "<command> :Not enough parameters\", so 3 means <command> is "
                 "ABSENT -- which is the defect this file exists for -- and 5 means "
                 "something was added to it.\n  line: %s", who, n, line);
    if (n != 4) {
        return;
    }
    TF_CHECK_MSG(strcmp(fields[0], "461") == 0,
                 "%s: the first parameter is \"%s\" and must be \"461\"\n"
                 "  line: %s", who, fields[0], line);
    TF_CHECK_MSG(strcmp(fields[1], client) == 0,
                 "%s: <client> is \"%s\" and must be \"%s\"\n  line: %s", who,
                 fields[1], client, line);
    TF_CHECK_MSG(strcmp(fields[2], verb) == 0,
                 "%s: <command> is \"%s\" and must be \"%s\". This is the field "
                 "that lets a client attribute the refusal to a verb, so a wrong "
                 "value here is a wrong ANSWER and not a formatting slip.\n"
                 "  line: %s", who, fields[2], verb, line);
    TF_CHECK_MSG(strcmp(fields[3], ":Not enough parameters") == 0,
                 "%s: the trailing text is \"%s\" and must be "
                 "\":Not enough parameters\"\n  line: %s", who, fields[3], line);
}

/* ===========================================================================
 * 1. THE LEGACY CLIENT: TWENTY PROBES, ONE FIELD LIST
 * ====================================================================== */
static void check_legacy_arity(test_client_t *c)
{
    size_t i;

    for (i = 0; i < sizeof k_arity / sizeof k_arity[0]; i++) {
        size_t from;
        size_t end;
        char found[512];

        from = mark(c);
        TF_CHECK_MSG(tc_send(c, k_arity[i].send) == 0,
                     "\"%s\" could not be sent (%s)", k_arity[i].send,
                     k_arity[i].why);
        end = mark(c);
        TF_CHECK_MSG(end > from,
                     "\"%s\" produced no window, so every claim below would be "
                     "about the read schedule rather than the wire", k_arity[i].send);

        if (find_461(tc_buffer(c), from, found, sizeof found) != 0) {
            TF_CHECK_MSG(strstr(tc_buffer(c) + from, " 461 ") != NULL,
                         "\"%s\" (%s) must be answered 461 and no line beginning "
                         "\":irc.test 461 \" appeared in its window.\n  window: %s",
                         k_arity[i].send, k_arity[i].why,
                         tc_buffer(c) + from);
            TF_CHECK_MSG(strstr(tc_buffer(c) + from, " 461 ") == NULL,
                         "\"%s\" was answered with something that is not 461 "
                         "at all\n  window: %s", k_arity[i].send,
                         tc_buffer(c) + from);
            continue;
        }
        expect_461_fields(found, k_arity[i].send, "alice", k_arity[i].verb);

        /* ONE 461, not two. A fix that added the field twice, or that answered a
         * wrong-arity line twice, satisfies every assertion above. */
        TF_CHECK_MSG(tf_count(tc_buffer(c) + from, " 461 ") == 1u,
                     "\"%s\" produced %zu 461 lines and must produce exactly one\n"
                     "  window: %s", k_arity[i].send,
                     tf_count(tc_buffer(c) + from, " 461 "),
                     tc_buffer(c) + from);
    }
}

/* ===========================================================================
 * 2. 451 MUST NOT GAIN A FIELD
 * ====================================================================== */
/* RFC 2812 5.2 writes 451 as "<client> :You have not registered" -- no field
 * before the text. It is the check this file's whole claim rests on: the fix is
 * "461 gains a command word", and a rule of "every refusal names the verb" would
 * give 451 one it does not have, and every 461 needle in the suite would still
 * pass. The window is closed by the PING, and the PING's own answer is a PONG
 * rather than a numeric, so the window holds exactly what the verb produced. */
static void check_451_has_no_command_field(int port)
{
    test_client_t fresh;
    char line[512];
    char fields[8][ARITY_MAX_FIELD];
    const char *at;
    size_t end;
    int n;

    tc_init(&fresh);
    TF_CHECK_MSG(tc_connect(&fresh, port) == 0,
                 "the fresh client could not connect");
    /* NICK but not USER: the registration gate is what answers, and the gate runs
     * BEFORE the handler, which is the whole point -- 451 is emitted by the
     * dispatcher and not by any of the twenty handlers above, so this case also
     * covers the one 461-shaped path the sweep cannot reach. */
    TF_CHECK_MSG(tc_send(&fresh, "NICK arity") == 0, "NICK send failed");
    TF_CHECK_MSG(tc_send(&fresh, "TOPIC") == 0,
                 "the pre-registration TOPIC failed");
    TF_CHECK_MSG(tc_expect(&fresh, " 451 ", T_IO_MS) == 0,
                 "an unregistered client's TOPIC must be answered 451");
    TF_CHECK_MSG(tc_send(&fresh, "PING :arity-451") == 0, "drain PING send failed");
    TF_CHECK_MSG(tc_expect(&fresh, "arity-451", T_IO_MS) == 0, "no drain PONG");
    end = (size_t)tc_received(&fresh);
    (void)end;

    at = strstr(tc_buffer(&fresh), ":" BIN_NAME " 451 ");
    TF_CHECK_MSG(at != NULL, "no \":irc.test 451 \" line on the fresh connection\n"
                             "  window: %s", tc_buffer(&fresh));
    if (at == NULL) {
        tc_close(&fresh);
        return;
    }
    TF_CHECK_MSG(at == tc_buffer(&fresh) || at[-1] == '\n',
                 "the 451 found is the tail of a longer line, not a line of its own");
    {
        size_t len = strcspn(at, "\r\n");

        if (len + 1u > sizeof line) {
            TF_CHECK_MSG(0, "the 451 line is %zu bytes, longer than this file's "
                         "%zu buffer", len, sizeof line);
            tc_close(&fresh);
            return;
        }
        memcpy(line, at, len);
        line[len] = '\0';
    }
    n = split_line(line, fields, 8);
    /* THREE parameters after the prefix is stripped: 451, <client>, :<text>. The
     * <client> field is 461's too, so it appears in both -- what 451 does NOT have
     * is the <command> that follows it, and a count of 4 is that fault. */
    TF_CHECK_MSG(n == 3,
                 "451 must have 3 parameters (451, <client>, :<text>) and has %d. "
                 "RFC 2812 5.2 gives it NO <command> field, so a 4 means a verb was "
                 "added to a numeric that does not have one.\n  line: %s", n, line);
    if (n == 3) {
        TF_CHECK_MSG(strcmp(fields[0], "451") == 0,
                     "451's first parameter is \"%s\" and must be \"451\"\n"
                     "  line: %s", fields[0], line);
        TF_CHECK_MSG(strcmp(fields[2], ":You have not registered") == 0,
                     "451's trailing text is \"%s\" and must be \":You have not "
                     "registered\"\n  line: %s", fields[2], line);
    }
    tc_close(&fresh);
}

/* ===========================================================================
 * 3. 482's FIELD IS THE CHANNEL, AND MUST STILL BE THE CHANNEL
 * ====================================================================== */
/* This is the failure mode a "prepend the command" rule produces on a numeric
 * that already has a middle parameter. 482 is "<client> <channel> :You're not
 * channel operator", so a fix that prepended blindly would render
 *
 *     :irc.test 482 bob MODE #ARITY :You're not a channel operator
 *
 * -- the channel demoted to the third field and a client parsing by position
 * looking for a channel called MODE.
 *
 * IT TAKES A SECOND CLIENT, and that is not tidiness: handle_join() gives +o to
 * whoever CREATED the channel, so the client that made #ARITY is an operator and
 * its own MODE +o SUCCEEDS. The only way to be a member without the flag is to join
 * somebody else's channel, so bob joins and the MODE is his. An earlier version of
 * this check asked the creator and would have passed against a node that answered
 * MODE +o with nothing at all, because there was no line in the window to fail on. */
static void check_482_keeps_its_channel(test_client_t *c)
{
    size_t from;
    size_t end;
    char line[512];
    char fields[8][ARITY_MAX_FIELD];
    const char *at;
    int n;

    from = mark(c);
    TF_CHECK_MSG(tc_send(c, "MODE " ARITY_CHAN " +o bob") == 0,
                 "the MODE +o failed");
    end = mark(c);
    TF_CHECK_MSG(end > from,
                 "the MODE +o produced no window, so the 482 claim below would be "
                 "about the read schedule rather than the wire");
    at = strstr(tc_buffer(c) + from, ":" BIN_NAME " 482 ");
    TF_CHECK_MSG(at != NULL,
                 "a +o by a non-operator must be answered 482 and no such line "
                 "appeared in the window.\n  window: %s", tc_buffer(c) + from);
    if (at == NULL) {
        return;
    }
    {
        size_t len = strcspn(at, "\r\n");

        if (len + 1u > sizeof line) {
            TF_CHECK_MSG(0, "the 482 line is longer than this file's buffer");
            return;
        }
        memcpy(line, at, len);
        line[len] = '\0';
    }
    n = split_line(line, fields, 8);
    /* FOUR parameters after the prefix is stripped: 482, <client>, <channel>,
     * :<text>. The field after <client> is the CHANNEL -- that is the whole point of
     * this check, because a rule of "prepend the command word" would render
     * `482 alice MODE #ARITY :...` and a client parsing by position would be looking
     * for a channel called MODE. */
    TF_CHECK_MSG(n == 4,
                 "482 must have 4 parameters (482, <client>, <channel>, :<text>) and "
                 "has %d. RFC 2812 5.2 gives it \"<client> <channel> :You're not "
                 "channel operator\" -- the field after <client> is the CHANNEL, so "
                 "a 5 means a verb was prepended to it.\n  line: %s", n, line);
    if (n == 4) {
        TF_CHECK_MSG(strcmp(fields[0], "482") == 0,
                     "482's first parameter is \"%s\" and must be \"482\"\n"
                     "  line: %s", fields[0], line);
        TF_CHECK_MSG(strcmp(fields[1], "bob") == 0,
                     "482's <client> is \"%s\" and must be \"bob\"\n  line: %s",
                     fields[1], line);
        TF_CHECK_MSG(strcmp(fields[2], ARITY_CHAN) == 0,
                     "482's <channel> is \"%s\" and must be \"" ARITY_CHAN "\"\n"
                     "  line: %s", fields[2], line);
        TF_CHECK_MSG(strcmp(fields[3], ":You're not a channel operator") == 0,
                     "482's trailing text is \"%s\"\n  line: %s", fields[3], line);
    }
}

/* ===========================================================================
 * 4. THE STANDARD-REPLIES CLIENT: THE VERB APPEARS EXACTLY ONCE
 * ====================================================================== */
/* The legacy field is added on the legacy branch only, and this is the assertion
 * that says so. `command` is already a `FAIL`'s own <command>, so prepending it
 * there would give
 *
 *     FAIL PRIVMSG PRIVMSG NEED_MORE_PARAMS :Not enough parameters
 *
 * -- the verb twice, the second time where a client reads <context>. */
static void check_fail_carries_the_verb_once(test_client_t *c)
{
    char line[512];
    char fields[8][ARITY_MAX_FIELD];
    const char *at;
    int n;

    TF_CHECK_MSG(tc_send(c, "PRIVMSG") == 0, "the bare PRIVMSG failed");
    TF_CHECK_MSG(tc_expect(c, " FAIL ", T_IO_MS) == 0,
                 "a standard-replies client must be answered FAIL for a "
                 "wrong-arity PRIVMSG");
    TF_CHECK_MSG(tc_send(c, "PING :fail-drain") == 0, "drain PING send failed");
    TF_CHECK_MSG(tc_expect(c, "fail-drain", T_IO_MS) == 0, "no drain PONG");

    at = strstr(tc_buffer(c), ":" BIN_NAME " FAIL ");
    TF_CHECK_MSG(at != NULL, "no \":irc.test FAIL \" line\n  window: %s",
                 tc_buffer(c));
    if (at == NULL) {
        return;
    }
    {
        size_t len = strcspn(at, "\r\n");

        if (len + 1u > sizeof line) {
            TF_CHECK_MSG(0, "the FAIL line is longer than this file's buffer");
            return;
        }
        memcpy(line, at, len);
        line[len] = '\0';
    }
    n = split_line(line, fields, 8);
    /* Five PARAMETERS after the prefix is stripped: FAIL, <target>, <command>,
     * <code>, :<description>. <command> is at index 2 and the code at index 3, so
     * a prepended command word would push the code to index 4 and render
     *
     *     FAIL carol PRIVMSG PRIVMSG NEED_MORE_PARAMS :Not enough parameters
     *
     * -- the verb twice, the second time where a client reads <context>. The
     * count is what catches it, and the <command> value is checked as well so the
     * failure says WHICH of the two faults it is. */
    TF_CHECK_MSG(n == 5,
                 "FAIL must have 5 parameters (FAIL, <target>, <command>, <code>, "
                 ":<description>) and has %d. A 6 means the command word was "
                 "prepended as well as passed, so a client reads the verb twice and "
                 "finds <code> where it expected <context>.\\n  line: %s", n, line);
    if (n == 5) {
        TF_CHECK_MSG(strcmp(fields[0], "FAIL") == 0,
                     "FAIL's first parameter is \"%s\" and must be \"FAIL\"\n"
                     "  line: %s", fields[0], line);
        TF_CHECK_MSG(strcmp(fields[1], "carol") == 0,
                     "FAIL's <target> is \"%s\" and must be \"carol\"\n  line: %s",
                     fields[1], line);
        TF_CHECK_MSG(strcmp(fields[2], "PRIVMSG") == 0,
                     "FAIL's <command> is \"%s\" and must be \"PRIVMSG\"\n"
                     "  line: %s", fields[2], line);
        /* INVALID_PARAMS, not NEED_MORE_PARAMS, and deliberately so: msg_verbs.c's
     * send_message() cannot tell a too-FEW PRIVMSG from a too-MANY one, so it passes
     * the code as an OVERRIDE rather than taking the table's answer. reply.h documents
     * that mechanism. The override is not what this check is about -- the parameter
     * COUNT above is -- and asserting the table's code here would fail on a correct
     * node. */
    TF_CHECK_MSG(strcmp(fields[3], "INVALID_PARAMS") == 0,
                 "FAIL's <code> is \"%s\" and must be \"INVALID_PARAMS\"\n"
                 "  line: %s", fields[3], line);
        TF_CHECK_MSG(strcmp(fields[4], ":Not enough parameters") == 0,
                     "FAIL's <description> is \"%s\"\n  line: %s", fields[4], line);
    }
    /* And the whole line, byte for byte, so the assertion above cannot be satisfied
     * by a differently-spelled line that happens to have five fields. */
    TF_CHECK_MSG(strcmp(line,
                         ":" BIN_NAME " FAIL carol PRIVMSG INVALID_PARAMS "
                         ":Not enough parameters") == 0,
                 "the FAIL line is not the expected line.\n  got:  %s\n  want: "
                 ":" BIN_NAME " FAIL carol PRIVMSG INVALID_PARAMS :Not enough "
                 "parameters", line);
    /* And no legacy 461 reached this connection at all: a client that negotiated
     * the capability is answered one way or the other, never both. */
    TF_CHECK_MSG(strstr(tc_buffer(c), " 461 ") == NULL,
                 "a 461 reached a client that negotiated standard-replies\n"
                 "  window: %s", tc_buffer(c));
}

int main(void)
{
    nf_node_t node;
    test_client_t legacy;
    test_client_t plain;
    test_client_t sreplies;

    memset(&node, 0, sizeof node);
    if (nf_spawn_binary(&node) != 0) {
        TF_CHECK_MSG(0, "could not spawn the node");
        return 1;
    }
    TF_CHECK_MSG(nf_expect(&node, "loop_running:", T_READY_MS) == 0,
                 "the node never reported its loop armed");

    /* THREE CONNECTIONS, and each exists because the other two cannot do its job.
     *
     * alice is the legacy client: she created #ARITY, runs the twenty-two-probe
     * sweep, and is the one whose 461 must still name its verb at the very end.
     *
     * bob joins alice's channel, so he is a member WITHOUT +o, which is the only
     * way to reach a 482 -- see check_482_keeps_its_channel(). He negotiates
     * nothing: a standard-replies client is answered `FAIL`, and the whole point of
     * the 482 check is the legacy numeric's field list.
     *
     * carol negotiates `standard-replies`, which is a different code path, and a
     * CAP REQ sent on alice would change the very branch the twenty-two probes above
     * are asserting. */
    tc_init(&legacy);
    register_client(&legacy, node.port, "alice", NULL);
    join_arity_channel(&legacy);

    check_legacy_arity(&legacy);
    check_451_has_no_command_field(node.port);

    tc_init(&plain);
    register_client(&plain, node.port, "bob", NULL);
    join_existing_channel(&plain, "bob");
    check_482_keeps_its_channel(&plain);

    tc_init(&sreplies);
    register_client(&sreplies, node.port, "carol", "standard-replies");
    check_fail_carries_the_verb_once(&sreplies);

    /* The legacy client is still the one answering 461 after all of that: a fix
     * that leaked the capability or left the legacy branch broken would show here
     * and nowhere else, because the two clients differ in exactly one exchange. */
    {
        char want[128];

        (void)snprintf(want, sizeof want,
                       ":%s 461 alice USERHOST :Not enough parameters\r\n",
                       BIN_NAME);
        TF_CHECK_MSG(tc_send(&legacy, "USERHOST") == 0,
                     "the closing USERHOST failed");
        TF_CHECK_MSG(tc_expect(&legacy, want, T_IO_MS) == 0,
                     "the legacy client must still answer 461 with its verb named, "
                     "after the standard-replies client has been served");
    }

    tc_close(&legacy);
    tc_close(&plain);
    tc_close(&sreplies);
    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");
    nf_free(&node);
    return 0;
}
