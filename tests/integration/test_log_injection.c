/* test_log_injection.c -- the log-only fields: no client byte in this node's own
 * output, and a measurement in place of every value that is withheld (#121).
 *
 * ---------------------------------------------------------------------------
 * WHY THIS FILE IS A BATTERY AND NOT A CASE PER FIELD
 * ---------------------------------------------------------------------------
 * The first pass at #121 fixed three FIELDS and left fourteen log-only sites
 * printing `%s` of a client-supplied string. They were found by putting a control
 * byte into every client-reachable command line and scanning the node's whole
 * stdout, not by reading -- and the measurement found 22 surviving bytes across
 * eight log lines. Reading found more: four more sites whose branches a single
 * pass through the verb table never reached.
 *
 * So this file is that measurement, committed. Its claim is one number:
 *
 *     AFTER A CLIENT HAS SENT A CONTROL BYTE IN EVERY POSITION A CLIENT CAN PUT
 *     ONE, THIS NODE'S OWN STDOUT CONTAINS NONE OF THEM.
 *
 * That is a stronger claim than "each site was fixed", because it also covers the
 * site nobody enumerated -- a new `printf("%s", client_value)` added tomorrow
 * would fail this test the first time anybody exercised the command that reaches
 * it, which is the only way a shape can be guarded.
 *
 * ---------------------------------------------------------------------------
 * WHY THE WHOLE BUFFER AND NOT A NEEDLE SEARCH
 * ---------------------------------------------------------------------------
 * "Is ESC in the log" answered with `strstr(node.out, "\033")` would be a weaker
 * claim than it looks: a node that stripped ESC but left BEL would pass a search
 * for one and fail a scan for the SET. So the assertion walks every byte and
 * refuses any member of the set except CR and LF, which are the log's own line
 * terminators and which no client byte can be -- `message_parse_n()` refuses both
 * inside a parameter, so their appearance here is the framing layer's and not a
 * field's.
 *
 * DEL IS IN THE SCAN for the reason the set contains it: it is invisible in a log
 * and `strstr` for it is as easy to get wrong as any other byte.
 *
 * ---------------------------------------------------------------------------
 * NO FIXED sleep() ANYWHERE (6.3). Every wait is a deadline wait, and every
 * command is followed by a `PING` whose PONG is the drain token -- numbered per
 * call, because `tc_expect()` searches the ACCUMULATED buffer and a reused token
 * would be satisfied by an earlier PONG with no read at all.
 * ---------------------------------------------------------------------------
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/connection.h"
#include "harness/irc_client.h"
#include "harness/node_fixture.h"
#include "harness/test_util.h"

#define T_IO_MS 15000

#define ESC "\033"
#define BEL "\007"
/* ESC [ 2 J -- erase display -- then BEL. One byte that moves the operator's
 * cursor and one that makes noise, which is the two halves of the hazard a log
 * reader would actually notice. */
#define X ESC "[2J" BEL

static unsigned g_drain_seq;

static void drain(test_client_t *c)
{
    char token[64];
    char line[128];

    (void)snprintf(token, sizeof token, "lg%u", g_drain_seq++);
    (void)snprintf(line, sizeof line, "PING :%s", token);
    TF_CHECK_MSG(tc_send(c, line) == 0, "drain PING failed");
    TF_CHECK_MSG(tc_expect(c, token, T_IO_MS) == 0,
                 "no PONG for drain token %s, so the buffer is not yet drained and "
                 "the scan below would be about the read schedule rather than about "
                 "what the node said", token);
}

/* Send `line`, then a drain token, and wait for the token's PONG.
 *
 * WHAT THIS DOES NOT DO, and the reason is worth stating because it looks like a
 * bug: it does not wait for `line` to be ANSWERED, and it does not know which
 * answer to wait for. Waiting for a specific one is not available here -- several
 * of the commands below answer with a numeric whose text echoes the parameter back
 * to the client, and a command whose echo the formatter refuses to render (a
 * trailing parameter holding a control byte makes 908 unrepresentable) produces NO
 * line at all, so a per-command needle would time out and the commands after it
 * would never be sent.
 *
 * AND WAITING FOR "\r\n" WOULD BE WORSE THAN USELESS, because `tc_expect()`
 * searches the ACCUMULATED buffer rather than the unread bytes: a CRLF left over
 * from an earlier line satisfies it instantly, so it would prove nothing and would
 * look like it proved something.
 *
 * THE DRAIN IS WHAT MAKES IT CORRECT INSTEAD. TCP is ordered, so by the time the
 * PONG for the token comes back the node has already read and dispatched every line
 * sent before it -- including `line`. That is a fact about the socket rather than
 * about the reply schedule, which is the kind of fact 6.3 wants. And the battery's
 * actual assertion runs after the node has EXITED, so nothing here depends on the
 * order in which the log lines were written.
 *
 * The token is numbered per call for the reason every drain in this tree numbers
 * one: `tc_expect()` searches everything received so far, so a reused token would be
 * satisfied by an earlier PONG with no read at all. */
static void poke(test_client_t *c, const char *line)
{
    char token[64];
    char ping[128];

    TF_CHECK_MSG(tc_send(c, line) == 0, "could not send \"%s\"", line);
    (void)snprintf(token, sizeof token, "lg%u", g_drain_seq++);
    (void)snprintf(ping, sizeof ping, "PING :%s", token);
    TF_CHECK_MSG(tc_send(c, ping) == 0, "drain PING failed after \"%s\"", line);
    TF_CHECK_MSG(tc_expect(c, token, T_IO_MS) == 0,
                 "no PONG for drain token %s, so \"%s\" was not dispatched before "
                 "the connection stopped answering -- which means the log lines it "
                 "should have produced were never written", token, line);
}

/* THE CLAIM. Every byte of the child's accumulated stdout, with the set refused. */
static void assert_log_clean(const nf_node_t *node, const char *what)
{
    size_t i;

    for (i = 0; i < node->out_len; i++) {
        const unsigned char ch = (unsigned char)node->out[i];

        if (ch == '\r' || ch == '\n') {
            continue;
        }
        TF_CHECK_MSG(ch > 0x1fu && ch != 0x7fu,
                     "%s: a byte from the log-injection set (0x%02x) reached this "
                     "node's own stdout, which is what an operator's terminal and "
                     "every tool that reads this log are looking at. ESC followed by "
                     "`[` is a CSI sequence any terminal executes, so a single "
                     "command from a socket that never registered can rewrite an "
                     "operator's screen.\\n  log: %s", what, ch, node->out);
    }
}

/* ---------------------------------------------------------------------------
 * log_line_has_tail(): "this line, after this prefix, carries this tail"
 * ---------------------------------------------------------------------------
 * FOR MATCHING A LOG LINE THAT CARRIES ONE UNSTABLE FIELD, and the reason this
 * exists is a Linux-only CI failure that cost a whole review cycle.
 *
 * The obvious way to assert a `cmd_*:` line is to write the whole thing out:
 *
 *     strstr(node.out, "cmd_unimplemented: fd=4 command=KILL "
 *                      "command_len=4 command_bad_bytes=0")
 *
 * and that is what this file did. It passes on macOS and fails on Linux, and the
 * `4` is the reason: it is the node's file descriptor for the client, which
 * depends on how many descriptors the process happens to hold open when that
 * connection is accepted -- the listener, the epoll/kqueue descriptor, the peer
 * link, the log, and whatever the allocator left open. Two platforms, one
 * descriptor-count difference, and a test asserting an implementation detail of
 * the kernel's descriptor table.
 *
 * NOTHING ELSE IN THE SUITE DID THIS, which is what made it an obvious mistake
 * rather than a house style: no other integration test pins `fd=N` anywhere, and
 * a convention nobody follows is a convention that is wrong.
 *
 * So the fd is excluded and EVERYTHING ELSE IS NOT. This helper finds the line
 * carrying `prefix`, confines the search to that line, and requires `tail`
 * somewhere in it -- which still pins the fields, their order, and their values,
 * because a line that lost `command_bad_bytes=` or reported the wrong length does
 * not contain that tail. The claim the assertion exists to make is about
 * `command=`, `command_len=` and `command_bad_bytes=`, and that claim is intact.
 *
 * WHY NOT A LOOSE `strstr` FOR THE TAIL ALONE: without the prefix anchor, the
 * tail could be satisfied by a DIFFERENT line, which is how "the value survived"
 * turns into "some line somewhere has these words in it". Confining the search to
 * the line that carries the prefix is what keeps the assertion pointed at the line
 * it names.
 *
 * CONFINED TO ONE LINE, and not to the rest of the buffer, because these lines are
 * newline-terminated and the next `cmd_*:` line starts with its own prefix: a
 * buffer-wide search for the tail would let one line's fields satisfy another's
 * prefix. Returns 1 when the line exists and carries the tail.
 */
static int log_line_has_tail(const char *log, const char *prefix, const char *tail)
{
    size_t want;
    const char *at;

    if (log == NULL || prefix == NULL || tail == NULL) {
        return 0;
    }
    want = strlen(tail);
    if (want == 0u) {
        return 0;
    }
    /* EVERY LINE CARRYING THE PREFIX IS CONSIDERED, not just the first, and that is
     * not a convenience -- it is the difference between working and not.
     *
     * `cmd_unknown:` appears many times in this battery, once per unrecognised
     * command word, and the lines differ: one carries a printable word verbatim,
     * another carries `-` with a length and a bad-byte count. Anchoring on the FIRST
     * occurrence and requiring the tail there fails as soon as the first `cmd_unknown:`
     * line happens to be a different one -- which is exactly what happened when this
     * helper was first written, and the failure looks like "the value is not printed"
     * rather than like "the helper looked in the wrong place".
     *
     * The first version DID anchor on the first occurrence, and it passed on the case
     * above it (`cmd_unimplemented:`, which appears once) and failed on this one. Two
     * assertions differing only in how many times their prefix occurs, with the
     * difference showing up as a content failure, is a trap worth writing down.
     *
     * Each candidate is still examined ONE LINE AT A TIME, so the tail can never be
     * satisfied by a different line's fields: the prefix and the tail have to be on
     * the same line, which is what keeps the assertion pointed at the line it names.
     */
    for (at = log; (at = strstr(at, prefix)) != NULL; at += strlen(prefix)) {
        const char *nl = strchr(at, '\n');
        size_t span = (nl != NULL) ? (size_t)(nl - at) : strlen(at);
        size_t i;

        if (span < want) {
            continue;
        }
        for (i = 0; i + want <= span; i++) {
            if (memcmp(at + i, tail, want) == 0) {
                return 1;
            }
        }
    }
    return 0;
}

/* ---------------------------------------------------------------------------
 * THE BATTERY, in the order a client can send it
 * ---------------------------------------------------------------------------
 * Pre-registration first, because that is where the exposure is: everything up to
 * and including `USER` needs no credential on this node, so a battery that started
 * after registration would not be testing the reachable half.
 */
static void case_no_client_byte_reaches_the_log(void)
{
    nf_node_t node;
    test_client_t c;
    char line[1024];
    char long_verb[96];
    size_t long_verb_len;

    TF_CHECK_MSG(nf_spawn_binary(&node) == 0, "could not spawn the node");
    tc_init(&c);
    TF_CHECK_MSG(tc_connect(&c, node.port) == 0, "tc_connect failed");

    /* PRE-REGISTRATION, with an ORDINARY nickname.
     *
     * An earlier version of this battery put the bytes in the `NICK` word itself,
     * which reads like the cheapest possible injection -- and is exactly as
     * reachable, but it cannot be the way this file registers: `NICK\033` is not
     * the verb `NICK`, so it is an unknown command and no nickname is ever set,
     * and the connection then fails to register on `USER` alone. The battery below
     * therefore registers cleanly and exercises the unprintable command word later,
     * on `KILL`, where it reaches the same two log lines.
     *
     * Registering here rather than after is still load-bearing: it is the proof
     * that the battery ran, and a battery that silently failed to register would
     * produce a pristine log and pass. */
    (void)tc_send(&c, "PASS secret");
    (void)tc_send(&c, "CAP LS");
    (void)tc_expect(&c, " CAP ", T_IO_MS);
    (void)tc_send(&c, "NICK vic");
    (void)tc_send(&c, "USER vic 0 * :Real vic");
    /* CAP END, because `CAP LS` -- answered above only to prove the node speaks
     * CAP -- opens the negotiation gate, and a connection inside it is HELD
     * (`reg_held: reason=CAP_NEGOTIATING`) no matter what NICK and USER said. */
    (void)tc_send(&c, "CAP END");
    TF_CHECK_MSG(tc_expect(&c, " 001 ", T_IO_MS) == 0,
                 "the connection never registered, so nothing after this point was "
                 "exercised and a clean scan would prove nothing");
    drain(&c);

    (void)tc_send(&c, "JOIN #T");
    TF_CHECK_MSG(tc_expect(&c, " 366 ", T_IO_MS) == 0, "the JOIN never completed");
    drain(&c);

    /* PING AND PONG: two log lines whose entire content is attacker-chosen and
     * unexamined. The cheapest injection on the node. */
    (void)tc_send(&c, "PING " X);
    (void)tc_expect(&c, "PONG", T_IO_MS);
    drain(&c);
    poke(&c, "PING :" X);
    poke(&c, "PONG " X);

    /* The server-mask family: refuse_foreign_server() names the client's own
     * argument on the way to a 402. */
    poke(&c, "LUSERS " X);
    poke(&c, "VERSION " X);
    poke(&c, "TIME " X);
    poke(&c, "STATS " X);
    poke(&c, "LINKS " X);

    /* CHOPER: reached only with TWO parameters, because the arity test refuses one
     * before the log line -- which is why an earlier battery that sent `CHOPER <ESC>`
     * alone never reached this branch and reported a clean log. */
    poke(&c, "CHOPER " X " pw");

    /* A KICK with an over-long reason reaches the `chan_kick_refused:` branch,
     * which names `m->params[0]` BEFORE `resolve_joined()` has validated it. The
     * reason has to exceed CHAN_MAX_KICK_REASON (255) to get there. */
    {
        char filler[300];
        size_t i;

        for (i = 0; i < sizeof filler - 1u; i++) {
            filler[i] = 'r';
        }
        filler[sizeof filler - 1u] = '\0';
        (void)snprintf(line, sizeof line, "KICK " X " vic :%s", filler);
        poke(&c, line);
    }

    /* The reference-tag grammar, on BOTH arms: `BATCH +ref` reaches
     * `batch_ref_refused:` (a tag that is not in the class) and `BATCH -ref`
     * reaches `batch_refused: reason=ILLEGAL_REF`. `batch_ref_valid()` accepts
     * alnum and '-' only, so every one of these is a refusal -- which is exactly
     * why the refusal is where the raw value used to be printed. */
    poke(&c, "BATCH +" X);
    poke(&c, "BATCH -" X);
    poke(&c, "BATCH -nosuch");
    /* AND THE REFERENCE-TAG FORM, which is a DIFFERENT SITE. `BATCH +ref` is an
     * argument and reaches `batch_refused: reason=INVALID_REFTAG`; the `+ref` that
     * `note_reference()` looks at is a CLIENT PREFIX INSIDE A TAG KEY, so the wire
     * form is `@+ref` on an ordinary command line. An earlier version of this battery
     * sent only the `BATCH` forms and so never reached `batch_ref_refused:` at all --
     * which is how a site survived a sweep that reported itself as complete. */
    poke(&c, "@+" X " WHOIS vic");

    /* The capability grammar, on all three of its log lines: an unknown
     * SUBCOMMAND, a refused REQ name and a refused DEL name. `sub` is
     * `m->params[0]` and is unbounded; the two name lists are bounded by
     * CAP_LS_MAX. */
    poke(&c, "CAP " X);
    poke(&c, "CAP REQ :" X);
    poke(&c, "CAP DEL :" X);

    /* SASL: the mechanism name is `m->params[0]` on the very first AUTHENTICATE,
     * and nothing bounds it before the refusal line. */
    poke(&c, "AUTHENTICATE " X);

    /* A KNOWN verb this build does not implement -- KILL is `fn == NULL` in the
     * table -- which is `cmd_unimplemented:` rather than `cmd_unknown:`. Both
     * name the same word, so both are in the battery: a fix that covered only the
     * unknown-command branch would leave the unimplemented one printing raw. */
    poke(&c, "KILL " X);
    poke(&c, "NOSUCHVERB");

    /* A COMMAND WORD LONGER THAN THE PRINT FIELD. `conn_text_logsafe()` withholds
     * rather than shortens -- a log line that cut a value in half would name
     * something the client did not send -- so this arrives as `-` with its true
     * length beside it. `CONN_LOG_FIELD_MAX` is 64 and this word is 80, which is the
     * only way that branch is reachable at all: every real verb in the tree is under
     * twenty bytes, so without this the withholding-on-length behaviour would be
     * code no test could reach and therefore code no fault could be found in. */
    {
        (void)snprintf(long_verb, sizeof long_verb,
                       "NOSUCHVERB%s", "0123456789012345678901234567890123456789"
                                      "0123456789012345678901234");
        long_verb_len = strlen(long_verb);
        TF_CHECK_MSG(long_verb_len > (size_t)CONN_LOG_FIELD_MAX,
                     "the long verb is %lu bytes and the print field is %d, so this "
                     "case cannot reach the withholding-on-length branch",
                     (unsigned long)long_verb_len, CONN_LOG_FIELD_MAX);
        poke(&c, long_verb);
    }

    /* THE SAME VERB WITH THE BYTES IN THE WORD. `KILL ` + X has a space, so the
     * verb is the printable word `KILL` and the hostile bytes are a parameter.
     * `KILL` + X has no space, so the verb itself is unprintable -- which is the
     * withheld case, and the one that reaches `cmd_unknown:` rather than
     * `cmd_unimplemented:`. Both are needed: a fix that covered one of the two
     * branches would leave the other printing raw, and they are the same
     * expression in the source. */
    poke(&c, "KILL" X);

    /* INVITE: the `not_a_nick` branch names `t.name`, which is a RESOLVED name.
     * It is in the battery as a POSITIVE CONTROL for "resolved means validated",
     * and the case below asserts what it prints. */
    poke(&c, "INVITE #T #T");

    /* TWO MORE SITES THE FIRST SWEEP MISSED, both found by re-running the
     * enumeration over the FIXED tree rather than by re-reading the original list.
     * Both are named here so the next sweep does not have to rediscover them.
     *
     * WHO's MASK. `chan_name_valid()` gates the channel branch above it, so a
     * channel mask never reaches the line -- but a mask that is NOT a channel falls
     * through to the fall-through print, which names the client's own argument.
     * My first battery sent `WHO <ESC>` and the log stayed clean, which I read as
     * "validated". It was not: the validation is on the OTHER branch. A clean log
     * from a battery is evidence about the branches the battery reached, and this
     * one had not reached this line.
     *
     * THE AUTHCID. `authcid` is decoded from a base64 payload into a stack buffer
     * and is therefore entirely client bytes -- and it is printed on the REJECTED
     * path, which is by definition a path where `account_name_wire_safe()` never
     * ran. The first battery sent `AUTHENTICATE <ESC>`, which reaches the mechanism
     * line and says nothing about the authcid. */
    poke(&c, "WHO " X);
    poke(&c, "AUTHENTICATE PLAIN "
             "AGFzAGwAaQBjAGwAaQBlAG4AYwB0AAAtAGIAeQBiAHUA");

    /* PRIVMSG to an unknown target and to a known one: `msg_refused: target=%s`
     * names `m->params[0]` on the unrenderable-source branch, which is documented
     * unreachable because `conn_hostmask()` cannot truncate a string built from
     * the three struct widths it renders. The command is sent anyway so that a
     * future change to that argument shows up here rather than in production. */
    poke(&c, "PRIVMSG " X " :hi");
    poke(&c, "PRIVMSG #T :hi");

    assert_log_clean(&node, "the log-injection battery");

    /* QUIT LAST, because it ends the connection. The reason is log-only -- there
     * is no quit cache and no NickServ -- so it is measured rather than filtered,
     * and this is the assertion that it is. */
    (void)tc_send(&c, "QUIT :" X);
    (void)tc_expect_eof(&c, T_IO_MS);
    /* The close-time lines and the reason are all printed by then, but the reaper
     * runs at the next fixed point of the loop, so the scan is done once the node
     * has actually exited rather than on a guess about the schedule. */
    TF_CHECK_MSG(nf_stop(&node) == 0, "the node did not exit cleanly");
    assert_log_clean(&node, "the log-injection battery, including QUIT");

    /* TWO LINES THAT MUST STILL NAME THEIR VALUE. Every site above withholds a
     * value that holds a control byte, and this is the half that would be lost if
     * "withhold" had been implemented as "never print the value": a log line whose
     * whole content is the verb has to still name the verb when the verb is a verb.
     *
     * `KILL` is the right one to pin because it is the ONLY verb that reaches
     * `cmd_unimplemented`, so this is the assertion that branch's value survived. */
    TF_CHECK_MSG(strstr(node.out, "cmd_unimplemented: fd=") != NULL,
                 "the node never logged a cmd_unimplemented line, so the branch this "
                 "assertion is about was not reached and the value cannot have been "
                 "checked.\n  log: %s", node.out);
    TF_CHECK_MSG(log_line_has_tail(node.out, "cmd_unimplemented: fd=",
                                  "command=KILL command_len=4 "
                 "command_bad_bytes=0") != 0,
                 "a KNOWN, PRINTABLE command word is no longer printed. `KILL` is "
                 "4 bytes with no control byte in it, so the value must be verbatim "
                 "and the count must be 0 -- a fix that withheld every value would "
                 "leave every `cmd_*:` line naming `-` and this log useless for the "
                 "question it exists to answer. The descriptor is deliberately "
                 "NOT in the needle: it is the node's fd for the client, it "
                 "differs between platforms and between runs, and pinning it "
                 "tested the kernel's descriptor table rather than this log. "
                 "Every other field on the line is pinned, in order.\n  log: %s",
                 node.out);

    /* AND THE WITHHELD CASE, which is the other half. `KILL ` + a control byte is
     * the same branch with a word that cannot be printed, and it must produce the
     * MEASUREMENT instead: the value withheld, the true length, and the count. */
    TF_CHECK_MSG(log_line_has_tail(node.out, "cmd_unknown: fd=",
                                  "command=- command_len=9 "
                 "command_bad_bytes=2") != 0,
                 "an UNPRINTABLE command word was not measured. `KILL` (4) plus ESC "
                 "(1) plus `[2J` (3) plus BEL (1) is 9 bytes carrying two members of "
                 "the set, so the line must carry `command=-` with the true length 9 "
                 "and 2 bad bytes -- the length and the count are what make a "
                 "withheld value diagnosable rather than mysterious.\n  log: %s",
                 node.out);

    /* AND THE PER-LINE CONFINEMENT IS LOAD-BEARING, asserted rather than assumed.
     *
     * The two cases above produce DIFFERENT lines -- one carrying the verbatim word,
     * one carrying `-` with a length and a bad-byte count -- and confining the search
     * to the line that carries the prefix is the only thing keeping each assertion
     * pointed at its own. Without it, a tail can be satisfied by another line's
     * fields, and that failure is invisible: the assertion still passes, for the
     * wrong line.
     *
     * So this is the negative of it, and it exists because the confinement was
     * removed under fault injection and NOTHING WENT RED. That is the useful shape of
     * this bug: a helper that quietly stopped doing what its name says, caught by no
     * assertion, in a suite where a strip that stopped stripping also went unnoticed
     * once. Here is the assertion that would have caught it. */
    TF_CHECK_MSG(log_line_has_tail(node.out, "cmd_unimplemented: fd=",
                                  "command=- command_len=9 "
                                  "command_bad_bytes=2") == 0,
                 "the WITHHELD case's fields were found on the VERBATIM case's line, "
                 "which means the helper is no longer confining its search to the line "
                 "that carries the prefix. Both lines exist in this log and carry "
                 "different values, so a helper ranging over the whole buffer would "
                 "satisfy either assertion from either line -- and every check here "
                 "would go on passing for the wrong reason.\n  log: %s", node.out);

    /* AND THE WITHHELD-BECAUSE-TOO-LONG CASE, the other `-`. Same verb, same
     * absence of a control byte, and a different reason -- so the two `-`s are only
     * distinguishable by the length beside them, which is the whole reason every
     * caller prints it. */
    {
        char needle[160];

        (void)snprintf(needle, sizeof needle,
                       "command=- command_len=%zu command_bad_bytes=0",
                       long_verb_len);
        TF_CHECK_MSG(log_line_has_tail(node.out, "cmd_unknown: fd=", needle) != 0,
                     "an over-long but PRINTABLE command word was not withheld with "
                     "its length; expected \"%s\". The zero count is what distinguishes "
                     "this from the unprintable case above, which has the same `-` and "
                     "a non-zero count -- so the two withholding reasons are only "
                     "separable because the length is printed. As above, the fd is "
                     "excluded because it is a descriptor number and not a property of "
                     "this log.\n  log: %s", needle,
                     node.out);
    }

    /* THE INVITE POSITIVE CONTROL, spelled out because it is the one site in the
     * battery that was ALREADY SAFE. `chan_invite_refused: ... target=%s` prints
     * `t.name`, and `t.name` exists only if `fanout_resolve()` returned non-zero --
     * so it is a channel name that passed `chan_name_valid()` or a nickname that
     * passed `valid_nick()`. `#T` is a channel this node owns, so a resolve to it
     * succeeds and the branch prints the RESOLVED name rather than the client's
     * argument. This asserts it is the resolved one, which is what makes "no filter
     * needed here" a checked claim rather than an assumption. */
    TF_CHECK_MSG(strstr(node.out, "chan_invite_refused: nick=vic target=#T "
                           "kind=2 reason=not_a_nick") != NULL,
                 "the INVITE refusal did not name the RESOLVED target `#T`. This is "
                 "the one site in the battery that needed no change, and the reason "
                 "is that `fanout_resolve()` only succeeds for a name that passed a "
                 "validator -- so the assertion is what proves it.\n  log: %s",
                 node.out);

    /* THE CLIENT IS CLOSED, and this is not tidiness -- it is a LeakSanitizer
     * failure on Linux.
     *
     * `tc_expect()` grows the client's read buffer with realloc() as bytes arrive,
     * and this case reads enough of them that the buffer is 4096 bytes by the end.
     * Nothing frees it: the client is a stack object, so there is no destructor to
     * run it, and the node being freed does not touch it. The process exits with
     * that allocation live, and LeakSanitizer -- which the macOS gate EXCLUDES,
     * because LSan does not exist on Darwin -- is the only thing that ever notices.
     *
     * So the failure is Linux-only and it was invisible here for two independent
     * reasons: the platform does not run the detector, and until this pass fixed the
     * fd pin the test EXITED at that assertion and never reached the end of the
     * case. Fixing the assertion is what exposed the leak, which is the usual
     * relationship between two fixes: the second one was always there.
     *
     * Every other case in this suite closes its clients for the same reason, and the
     * ones that do not are not passing on Linux either. */
    tc_close(&c);
    nf_free(&node);
}

int main(void)
{
    case_no_client_byte_reaches_the_log();

    tf_done("log-injection");
    return 0;
}
