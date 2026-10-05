/* test_relay_shape.c -- the general shape behind four bugs: a client parameter
 * broadcast verbatim instead of the field the node stored (#121).
 *
 * ---------------------------------------------------------------------------
 * WHY A SOURCE TEST, STATED BEFORE ANYTHING ELSE
 * ---------------------------------------------------------------------------
 * The defect this guards is a SHAPE, and the reason is that a field and its
 * announcement are two copies of one value:
 *
 *   - `handle_topic()` stored `ch->topic` and broadcast `m->params[1]`. The store
 *     was filtered, the announcement was not, and every member of the channel got
 *     the raw bytes while a later joiner got the clean ones -- one field, two
 *     answers, and the stored one was the one nobody could see the problem in.
 *   - `handle_mode()`'s `+b` arm did the same with a ban mask, which is worse
 *     because the stored copy is what `chan_banned()` enforces.
 *   - `handle_kick()` and `handle_part()` have no stored copy at all, so the same
 *     question has a different answer there: strip the parameter, because a strip
 *     is what "don't relay the client's bytes" means when there is no field.
 *
 * None of those is a RUNTIME failure that a protocol test can see. Every one of
 * them produces entirely reasonable wire output on the fixed build and entirely
 * unreasonable wire output on the broken one, and the difference is visible only
 * in whether the bytes on the wire are the bytes the node decided to store. That is
 * a property of the CODE, and looking is the only way to check a property of the
 * code -- which is the same answer §2.5.4 gives for "no close() outside the reaper",
 * and the reason `tf_read_code()` exists.
 *
 * So the runtime half is in the files where it belongs and this file carries the
 * structural half:
 *
 *   test_control_bytes.c   the exact line a member receives, for the topic, the
 *                          kick reason, the part reason and the ban mask, plus
 *                          the ENFORCED ban that is the only place the stored copy
 *                          is observable at all.
 *   test_fed_relay.c       the TOPIC forward arm, including the two things that arm
 *                          cannot reach.
 *   THIS FILE              the invariant that would have caught all four.
 *
 * ---------------------------------------------------------------------------
 * THE INVARIANT
 * ---------------------------------------------------------------------------
 * In `chan_verbs.c`, no array named `params` is ever assigned from `m->params`.
 *
 * `m->params` is the client's own bytes. `params` is the array every emission in
 * this file hands to `deliver_state_change()`. An assignment between them is the
 * whole defect: the emission says one thing and the node's state says another, and
 * the only reader who can tell is a human comparing two lines.
 *
 * ---------------------------------------------------------------------------
 * AND WHY IT IS NOT "NO CLIENT STRING REACHES A CLIENT"
 * ---------------------------------------------------------------------------
 * That would be false and asserting it would be a lie. `msg_verbs.c` passes a
 * client's PRIVMSG text to `fanout_deliver()`, and it must: relaying a message is
 * what the node is for, the text is the message, and filtering it is a decision
 * about IRC rather than about this shape. This file's claim is scoped to
 * `chan_verbs.c` and to the `params` arrays, and the exemption is named here
 * rather than left for the next reader to wonder about.
 *
 * ---------------------------------------------------------------------------
 * WHY IT IS NOT VACUOUS, WHICH IS THE PART THAT ACTUALLY MATTERS
 * ---------------------------------------------------------------------------
 * A source test that asserts "zero occurrences of a pattern" passes trivially on a
 * file the pattern was renamed out of. This file counts what it expects to FIND as
 * well as what it expects not to, and fails if the count of emissions drops to
 * zero -- so deleting the four sites, or renaming `deliver_state_change`, or
 * emptying the file, turns this red instead of quietly vacuous. That is the same
 * discipline `test_close_sites.c` uses for `close()`, and for the same reason: a
 * structural assertion whose subject can disappear has stopped asserting anything.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "harness/test_util.h"

#define RELAY_FILE "src/core/chan_verbs.c"

/* Occurrences of `needle` in `code`, as a NON-OVERLAPPING count. Written out here
 * rather than pulled from the harness because `tf_count()` counts a STRING in a
 * buffer and this needs a count of a token in code with its comments already
 * stripped -- the same distinction `test_close_sites.c` draws. */
static size_t occurrences(const char *code, const char *needle)
{
    size_t n = 0;
    size_t len = strlen(needle);
    const char *p = code;

    while ((p = strstr(p, needle)) != NULL) {
        n++;
        p += len;
    }
    return n;
}

static int is_ident_char(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '_';
}

/* How many assignments of the form `params[...] = <something m->params...>` are in
 * `code`. That is the count this file's claim is about, and it is zero on the
 * fixed tree.
 *
 * THE MATCH IS ON THE WHOLE TOKEN, and that is deliberate. A plain search for the
 * text `params[` would also find `extended_params[` and `s->chan_params[`, so
 * matching a substring would have made the invariant satisfiable by renaming an
 * array -- which is precisely the vacuity the non-vacuity check below exists to
 * catch, so the two defects would have cancelled. The character before the match
 * must not be an identifier character and must not be `>` or `-`, which excludes
 * both the longer names and a member access. */
static size_t raw_param_assignments(const char *code, char *first_out,
                                    size_t first_cap)
{
    size_t n = 0;
    const char *p = code;

    if (first_out != NULL && first_cap != 0u) {
        first_out[0] = '\0';
    }
    while ((p = strstr(p, "params[")) != NULL) {
        const char *eq;
        const char *semi;

        if (p > code && (is_ident_char(p[-1]) || p[-1] == '>' || p[-1] == '-')) {
            p += 8;
            continue;
        }
        /* The statement runs to the next `;`, which is safe because
         * `tf_read_code()` has removed the string literals -- without that, a `;`
         * inside a format string would end the statement early and the check would
         * be reading the wrong text. */
        semi = strchr(p, ';');
        if (semi == NULL) {
            break;
        }
        eq = (const char *)memchr(p, '=', (size_t)(semi - p));
        if (eq != NULL) {
            const char *rhs = strstr(eq, "m->params[");

            if (rhs != NULL && rhs < semi) {
                /* The offending statement itself, so a failure names the line to go
                 * and look at instead of saying only that there is one. Quoted to a
                 * bound: the statement is short by construction and a fixed buffer
                 * keeps this a test rather than an allocation. */
                if (first_out != NULL && first_cap != 0u && n == 0u) {
                    size_t len = (size_t)(semi - p) + 1u;

                    if (len > first_cap) {
                        len = first_cap;
                    }
                    memcpy(first_out, p, len - 1u);
                    first_out[len - 1u] = '\0';
                }
                n++;
            }
        }
        p = semi + 1;
    }
    return n;
}

static void case_no_emission_carries_a_client_parameter(void)
{
    char *code;
    size_t len = 0;
    size_t emissions;
    size_t offenders;
    char first[192];

    code = tf_read_code(RELAY_FILE, &len);
    TF_CHECK_MSG(code != NULL, "could not read %s (is IRCSERVE_SRC_DIR set?)",
                 RELAY_FILE);
    TF_CHECK_MSG(len > 0, "%s read as empty, so every assertion below would pass "
                 "on a file this test did not look at", RELAY_FILE);

    /* THE SUBJECT IS STILL THERE. Without this, "zero raw assignments" is
     * satisfiable by deleting the emissions, and a test that can be satisfied by
     * deleting the thing it is about is not a test. Nine is what the tree has:
     * five in handle_mode(), and one each in chan_admit(), handle_part()'s forward
     * arm, handle_topic()'s forward arm, handle_topic()'s owned arm, handle_kick(),
     * notify_invite() and chan_member_leave(). It is written as a RANGE rather than
     * an equality because a new verb that emits something legitimately adds one, and
     * a test that fails on an addition is a test that gets deleted. */
    emissions = occurrences(code, "deliver_state_change");
    TF_CHECK_MSG(emissions >= 7u,
                 "%s holds %lu call(s) to deliver_state_change() and this test "
                 "expects at least 7. Either the emissions were renamed or removed -- "
                 "which would make the zero-below vacuous -- or the invariant moved "
                 "somewhere this file does not look. A structural assertion whose "
                 "subject can disappear has stopped asserting anything.",
                 RELAY_FILE, (unsigned long)emissions);

    /* AND THE INVARIANT. */
    offenders = raw_param_assignments(code, first, sizeof first);
    TF_CHECK_MSG(offenders == 0u,
                 "%s assigns an emission's parameter array from the client's own "
                 "parameter %lu time(s). Every one of those is a field and its "
                 "announcement being two different values: the emission says one "
                 "thing and the node's state says another, and the only reader who "
                 "can tell is a human comparing two lines. `handle_topic()` did this "
                 "with the topic and `handle_mode()` with a ban mask, and the ban is "
                 "the worse of the two because the stored copy is what chan_banned() "
                 "enforces. The fix is not to strip at the assignment -- it is to "
                 "hand the emission the value the node decided on: `ch->topic`, a "
                 "stripped copy, or `effective` computed once above both the store "
                 "and the broadcast.\n  offending statement: %s",
                 RELAY_FILE, (unsigned long)offenders, first);

    /* THE EXEMPTION, CHECKED RATHER THAN ASSERTED IN PROSE. msg_verbs.c really does
     * relay a client's PRIVMSG text to a fan-out, and this file's claim is scoped so
     * that it does not have to pretend otherwise. Asserting the exemption EXISTS is
     * what stops the scope from being quietly widened: a future reader who extends
     * this invariant to msg_verbs.c will fail here and be told exactly why. */
    {
        char *msg = tf_read_code("src/core/msg_verbs.c", &len);

        TF_CHECK_MSG(msg != NULL, "could not read src/core/msg_verbs.c");
        TF_CHECK_MSG(strstr(msg, "fanout_deliver") != NULL,
                     "src/core/msg_verbs.c no longer calls fanout_deliver() at all, so "
                     "the PRIVMSG exemption this file's scope depends on has changed "
                     "shape and the scope needs revisiting rather than being assumed.");
        free(msg);
    }

    free(code);
}

int main(void)
{
    case_no_emission_carries_a_client_parameter();

    tf_done("relay-shape");
    return 0;
}
