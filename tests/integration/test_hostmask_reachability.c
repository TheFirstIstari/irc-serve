/* test_hostmask_reachability.c -- #134: the "documented unreachable" claim, CHECKED.
 *
 * ===========================================================================
 * WHAT THIS IS FOR, STATED AS THE FAILURE IT REPLACES
 * ===========================================================================
 * `src/core/msg_verbs.c` answers 404 from a branch guarded by
 *
 *     if (conn_hostmask(c, prefix, sizeof prefix) == 0) {
 *
 * and the paragraph above it argued -- in a comment, which is the one form of an
 * unreachable claim this project has learned three times not to accept -- that the
 * branch cannot execute, because `CONN_HOSTMASK_MAX` is the sum of the three
 * `conn_t` field widths and `conn_hostmask()` would have to truncate a string built
 * from those same widths.
 *
 * Two things were wrong with it being a comment.
 *
 *   1. A COMMENT ABOUT UNREACHABLE CODE IS NOT REVIEWED WITH THE CHANGE THAT MAKES
 *      IT REACHABLE. Nothing flags the branch when somebody widens a field, and
 *      nothing flags the `printf` on the line below it when somebody relaxes the
 *      resolver that was, in the argument, validating the target for it. This line
 *      carried a client-supplied `<msgtarget>` into `printf("%s")` with no filter,
 *      and it survived a full audit of every `printf` site in the node (#121)
 *      precisely because no test could reach the branch that prints it.
 *
 *   2. A BRANCH NOBODY CAN REACH IS A BRANCH NOBODY MAINTAINS, and the cost is not
 *      hypothetical here: the fix for the exposure was one call, and the decision
 *      about the branch was a decision about code that by the argument does not
 *      exist. #134 was filed because that combination had been left sitting in a
 *      file for long enough to be found by a different audit.
 *
 * So the claim is now established HERE, from the source, by a test that goes red.
 * Not by asserting the branch is dead -- nothing can do that from outside the
 * process -- but by establishing the three premises the claim rests on, each of
 * which can be broken by an edit that is otherwise unremarkable:
 *
 *   P1  `CONN_HOSTMASK_MAX` is WRITTEN AS THE SUM of `sizeof` of the three fields
 *       plus 3, not as a literal. A literal is a number that stops being true when
 *       a field grows, and nothing else in the tree would notice.
 *   P2  The three fields are FIXED-SIZE ARRAYS. This is the premise P1 hides: if
 *       `conn_t::host` were a `char *`, `sizeof` would be 8 on every platform and
 *       the derivation would still "hold" while proving nothing at all. A test that
 *       checked only P1 would pass against that change.
 *   P3  `conn_hostmask()`'s ONLY FORMAT is `"%s!%s@%s"` over exactly those three
 *       fields, and its only failure condition is truncation. A fourth `%s`, or a
 *       different separator, breaks the arithmetic that makes the branch dead --
 *       `"%s@%s@%s"` is one byte wider and `snprintf` reports it.
 *
 * Together P1-P3 are the claim. Together they are also why the branch is KEPT: the
 * 404 is a correct wire behaviour, because a line whose source cannot be rendered
 * must not be sent, and the alternative is a prefix-less line on the wire. What is
 * not acceptable is the injection site underneath it, and that is fixed
 * independently of reachability -- see the block in msg_verbs.c.
 *
 * ===========================================================================
 * AND THE FOURTH CHECK, WHICH IS THE ONE THAT GENERALISES
 * ===========================================================================
 * P1-P3 say this branch is dead. They do not say the LINE is safe, and a test that
 * only proved deadness would let the next edit put anything in the dead branch --
 * which is precisely how the defect survived. So this file also states the rule
 * that makes dead code safe to leave:
 *
 *   NO `printf` IN msg_verbs.c MAY NAME `m->params[...]` DIRECTLY.
 *
 * That is a small rule with a large blast radius, and it is checkable without a C
 * parser because `tf_read_code()` has already stripped comments and string
 * literals -- which matters twice over: the file's own comments name `m->params[0]`
 * dozens of times, and a check that matched them would be a check that could only
 * ever fail.
 *
 * It is deliberately a RULE and not a list of sites. There are eight other
 * `conn_hostmask() == 0` defensive branches in the node (seven in chan_verbs.c, one
 * in account.c), and all eight are bare `return`/`continue` with no log line at
 * all, so there is nothing to list. The rule covers the next one somebody writes
 * without this file having been edited.
 *
 * AND THE RULE IS ABOUT THE ARGUMENT, NOT THE MENTION -- which is the difference
 * between a rule and a tripwire. `strlen(m->params[0])` and
 * `conn_text_bad_count(m->params[0])` in the same statement are how the length and
 * the bad-byte count get onto the log line, and they are exactly what connection.h's
 * Rule 1 asks for. So the check walks the argument list and fails only when a
 * `m->params[...]` is an argument IN ITS OWN RIGHT rather than the operand of a
 * measurement. The first version of this check flagged the mere mention and was
 * red against the fix it was written for, which is the check crying wolf on its own
 * subject.
 *
 * ===========================================================================
 * NO SKIP, zero, AND NO BUILD-CONFIGURATION DEPENDENCE
 * ===========================================================================
 * Every assertion is a source inspection. There is no skip because there is no
 * condition to skip on: this file does not run a node, does not open a socket and
 * does not need a crypto library, so it asserts the same things in the TLS build
 * and the plaintext one. A check that only ran in one configuration would be a
 * configuration in which the rule is unchecked.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "harness/test_util.h"

/* Read one source file with comments and string literals stripped, INTO A CALLER'S
 * BUFFER, and this signature is the fix for the leak this file shipped with.
 *
 * THE FIRST VERSION returned a `char *` from `tf_read_code()` and every caller had to
 * `free()` it. Linux's LeakSanitizer found the one that did not:
 *
 *     Direct leak of 65536 byte(s) in 1 object(s)
 *     SUMMARY: AddressSanitizer: 65536 byte(s) leaked
 *
 * 65536 is `tf_read_code()`'s initial `cap`, so the trace names the harness function
 * and not the test -- and that is the shape of the defect. The obligation had left
 * the harness through a one-line wrapper, so no reading of the harness could have
 * found it and no sweep of the harness's OWN callers could see it either, because the
 * caller of the wrapper is not a caller of the harness. That is `audit-teardown.py`'s
 * stated limitation ("it cannot tell a helper from its caller") arriving as a real
 * leak rather than as a caveat.
 *
 * SO THERE IS NO BUFFER TO FORGET NOW. `dst` is the caller's, the function owns
 * nothing, and no path through this file can leak -- including the assertion-failure
 * paths, which is the other half of why this was invisible: `TF_CHECK_MSG` calls
 * `exit(1)`, and a heap buffer was still live at that point. A caller-provided
 * buffer is correct on every exit path, which is the property a returned pointer
 * does not have.
 *
 * A failure to read is a hard error here rather than something each caller
 * re-checks, because every use below would otherwise have to carry its own "did the
 * file open?" assertion and a missing file would read as "the pattern was absent" --
 * the exact vacuous-pass this file exists to avoid. The buffer is NOT silently
 * truncated when a file is too large; `tf_read_code_into()` refuses, and that is said
 * here so the next reader does not assume otherwise. */
static void read_src(char *dst, size_t cap, const char *rel)
{
    const long n = tf_read_code_into(dst, cap, rel, NULL);

    TF_CHECK_MSG(n >= 0,
                 "could not read %s into %lu bytes -- every check below would pass "
                 "vacuously if a source file it inspects cannot be read, and a source "
                 "check that silently examines half a file reports clean for a reason "
                 "nobody can see", rel, (unsigned long)cap);
}

/* Does `hay` contain `needle`? A named wrapper rather than strstr at each call
 * site, because a bare strstr call in a test is a claim a reader has to re-derive
 * and this file's whole point is that claims should be legible. */
static int has(const char *hay, const char *needle)
{
    return (hay != NULL && needle != NULL && strstr(hay, needle) != NULL) ? 1 : 0;
}

/* Collapse every run of whitespace to one space, and NUL-terminate.
 *
 * WHY, because it is not a convenience: `conn_t`'s three fields are declared with
 * the type and the name padded into a column (`char        nick[64];`), so a
 * needle of `char nick[` matches nothing and the P2 check would pass on a tree
 * where all three fields had become pointers. A check whose needle has to match
 * one particular column alignment is a check that stops checking the moment
 * somebody runs a formatter -- and a check that reports clean because it stopped
 * matching is worse than no check, because it is now evidence.
 *
 * The width is deliberately NOT part of any needle, for the reason the P1 comment
 * gives: `[64]` is a number that is supposed to be free to change, and a test that
 * pinned it would fail on a legitimate widening and pass on a pointer. */
static void squash(char *s)
{
    char *w = s;

    if (s == NULL) {
        return;
    }
    while (*s != '\0') {
        if (*s == ' ' || *s == '\t' || *s == '\n' || *s == '\r') {
            while (*s == ' ' || *s == '\t' || *s == '\n' || *s == '\r') {
                s++;
            }
            *w++ = ' ';
            continue;
        }
        *w++ = *s++;
    }
    *w = '\0';
}

/* ---------------------------------------------------------------------------
 * P1: CONN_HOSTMASK_MAX IS A DERIVATION, NOT A NUMBER
 * ---------------------------------------------------------------------------
 * The check is on the WRITTEN FORM and not on a recomputation, because what can
 * go stale is the form: someone who typed `130` there would have a correct number
 * today and a wrong one the day a field grows, and a test that recomputed the sum
 * would agree with the literal forever. So the assertion is that the macro's body
 * still names all three fields and still adds 3, which is what makes it track them.
 *
 * The `3u` is the two separators plus the NUL, and it is asserted by name rather
 * than left implicit: a derivation that summed the three widths and nothing else
 * would be one byte short, which is a defect this test could not otherwise see.
 */
static void check_width_is_derived(void)
{
    char hdr[TF_SRC_MAX];

    read_src(hdr, sizeof hdr, "src/core/connection.h");

    TF_CHECK_MSG(has(hdr, "CONN_HOSTMASK_MAX"),
                 "connection.h no longer defines CONN_HOSTMASK_MAX at all. Every "
                 "conn_hostmask() caller sizes its buffer with it, so this is a "
                 "compile failure rather than a claim -- but the file has changed "
                 "and the claims in msg_verbs.c about it are now unverified.");
    TF_CHECK_MSG(has(hdr, "sizeof(((conn_t *)0)->nick)"),
                 "CONN_HOSTMASK_MAX no longer derives from conn_t::nick. If it was "
                 "replaced by a literal, the buffer can be one byte short of the "
                 "string conn_hostmask() renders and the 404 branch in "
                 "msg_verbs.c stops being unreachable -- which is the whole "
                 "unreachability argument, now stated as something the build holds.");
    TF_CHECK_MSG(has(hdr, "sizeof(((conn_t *)0)->user)"),
                 "CONN_HOSTMASK_MAX no longer derives from conn_t::user. See the "
                 "nick term's message: the same one-byte-short failure, on a "
                 "different field.");
    TF_CHECK_MSG(has(hdr, "sizeof(((conn_t *)0)->host)"),
                 "CONN_HOSTMASK_MAX no longer derives from conn_t::host. See the "
                 "nick term's message: the same one-byte-short failure, on the "
                 "field whose width the KEEPALIVE and SASL paths also bound.");
    TF_CHECK_MSG(has(hdr, "+ 3u"),
                 "CONN_HOSTMASK_MAX's derivation no longer adds 3. That 3 is the "
                 "'!' and the '@' plus the NUL, so a derivation that sums only the "
                 "three widths is exactly one byte short of the string "
                 "conn_hostmask() builds -- and 'exactly one byte short' is the "
                 "condition that makes the 404 branch reachable.");
}

/* ---------------------------------------------------------------------------
 * P2: THE THREE FIELDS ARE ARRAYS, NOT POINTERS
 * ---------------------------------------------------------------------------
 * This is the premise P1 cannot see. `sizeof(((conn_t *)0)->host)` is 8 on every
 * platform when `host` is a `char *`, so the derivation would still be written the
 * way this test wants it and would prove nothing: a pointer field is unbounded,
 * `conn_hostmask()` could truncate, and the branch WOULD be live.
 *
 * The assertions are on the declaration TEXT after comment-stripping, and each is
 * a whole declaration rather than a fragment, so `char host[64]` matches and
 * `char *host` does not. `tf_read_code()` strips comments first, so the prose in
 * connection.h that discusses these fields cannot satisfy any of them.
 */
static void check_fields_are_arrays(void)
{
    char hdr[TF_SRC_MAX];

    /* THE FUNCTION THAT LEAKED, and the line above is the whole of the change: it
     * used to be `char *hdr = read_src(...)` with no `free()` anywhere below, and
     * this was the only leak Linux's LeakSanitizer reported in 98 tests. Nothing
     * else in this file leaked, which `leaks --atExit` over all 98 binaries confirms
     * -- see the header. */
    read_src(hdr, sizeof hdr, "src/core/connection.h");

    squash(hdr);

    TF_CHECK_MSG(has(hdr, "char nick["),
                 "conn_t::nick is not declared as a fixed-size array in "
                 "connection.h. CONN_HOSTMASK_MAX is computed from its sizeof, and a "
                 "pointer would make that a constant -- so the derivation this file "
                 "checks would still be written the right way while meaning nothing.");
    TF_CHECK_MSG(has(hdr, "char user["),
                 "conn_t::user is not declared as a fixed-size array in "
                 "connection.h. See the nick assertion: same premise, same failure.");
    TF_CHECK_MSG(has(hdr, "char host["),
                 "conn_t::host is not declared as a fixed-size array in "
                 "connection.h. See the nick assertion: same premise, same failure. "
                 "This one matters most, because host is the field a peer controls "
                 "most directly -- it is what accept() observed.");
}

/* ---------------------------------------------------------------------------
 * P3: conn_hostmask() RENDERS EXACTLY THOSE THREE FIELDS
 * ---------------------------------------------------------------------------
 * The arithmetic in P1 is only the width of the buffer; P3 is the claim that the
 * string being measured is the string that gets built. A separator wider than one
 * byte, or a fourth field, breaks the identity.
 *
 * `tf_read_code()` strips STRING LITERALS, which is normally what makes a check
 * precise and is exactly wrong here -- so this one reads the file with
 * `IRCSERVE_SRC_DIR` directly rather than through `tf_read_code()`. The cost is
 * that this assertion can now match the format string inside a COMMENT too, and
 * the mitigation is that the needle below includes the full call
 * (`snprintf(out, cap, "%s!%s@%s", c->nick, c->user, c->host)`), which no comment
 * in the file quotes in that form.
 */
static void check_render_is_three_fields(void)
{
    FILE *f;
    /* 512 KiB, and that is not a guess: connection.c is over 16 KiB, so a smaller
     * buffer would truncate it and this check would report the format string
     * absent for a file that contains it. Truncation fails LOUDLY here rather than
     * silently -- which is the only acceptable direction for a source inspection,
     * and the reason the read is followed by an assertion rather than a search
     * over whatever happened to fit. */
    static char buf[512u * 1024u];
    size_t n;
    int found = 0;

    TF_CHECK_MSG(tf_count("x", "x") == 1u, "tf_count is broken, which would make "
                 "every assertion below vacuous");

    f = fopen(IRCSERVE_SRC_DIR "/src/core/connection.c", "rb");
    TF_CHECK_MSG(f != NULL,
                 "could not open src/core/connection.c. This check reads the file "
                 "directly rather than through tf_read_code() because it is about a "
                 "FORMAT STRING, and tf_read_code() strips those by design.");
    n = fread(buf, 1u, sizeof buf - 1u, f);
    fclose(f);
    buf[n] = '\0';
    TF_CHECK_MSG(n < sizeof buf - 1u,
                 "src/core/connection.c did not fit the read buffer, so this check "
                 "inspected a PREFIX of the file and would report the format string "
                 "absent for a file that has it. Enlarging the buffer is the fix; "
                 "shrinking the assertion is not.");

    found = (strstr(buf, "\"%s!%s@%s\", c->nick, c->user, c->host)") != NULL) ? 1 : 0;
    TF_CHECK_MSG(found,
                 "conn_hostmask() no longer renders exactly \"%%s!%%s@%%s\" over "
                 "c->nick, c->user and c->host. Whatever it renders now is a "
                 "different length from the one CONN_HOSTMASK_MAX is derived from, "
                 "so the 404 branch in msg_verbs.c is no longer provably "
                 "unreachable -- and this file's P1 and P2 assertions would still "
                 "pass, which is the reason this one exists.");
}

/* ---------------------------------------------------------------------------
 * THE RULE: NO printf IN msg_verbs.c NAMES m->params[...] DIRECTLY
 * ---------------------------------------------------------------------------
 * Read through `tf_read_code()`, so comments and string literals are already gone
 * and a match is a match on CODE. That is not a convenience: this file's
 * predecessor -- the comment this test replaces -- names `m->params[0]` about a
 * dozen times, and a check that matched prose would be a check that could only
 * ever fail.
 *
 * `m->params[...]` rather than `params[...`, because `msg_verbs.c` has local
 * `params` arrays in several functions that are this node's own copies and are
 * fine to print; the rule is about the parse tree's array, which is the client's
 * bytes.
 */
static void check_no_raw_params_in_printf(void)
{
    char code[TF_SRC_MAX];
    const char *at;

    read_src(code, sizeof code, "src/core/msg_verbs.c");
    at = code;

    while (at != NULL && *at != '\0') {
        const char *call = strstr(at, "printf(");
        const char *stmt_end;
        const char *arg;
        int depth;

        if (call == NULL) {
            break;
        }
        /* ONE STATEMENT, not to the next `printf(`: the parentheses nest, and a
         * printf whose format string mentions another function would otherwise
         * split the scan in the wrong place. Tracked by nesting depth so a `;`
         * inside a nested call -- which none of this file's statements has -- does
         * not end the scan early. Ending it early is the harmless direction: it
         * makes the statement shorter, so it can only miss a violation, and the
         * next iteration re-finds the same `printf` and stops. */
        depth = 0;
        stmt_end = call;
        for (; *stmt_end != '\0'; stmt_end++) {
            if (*stmt_end == '(') {
                depth++;
            } else if (*stmt_end == ')') {
                depth--;
                if (depth == 0) {
                    break;
                }
            } else if (*stmt_end == ';' && depth <= 1) {
                break;
            }
        }
        if (*stmt_end == '\0') {
            break;
        }
        /* WALK THE ARGUMENTS. Splitting on `;` is enough to bound the statement;
         * splitting the ARGUMENT list on commas is what makes the rule about the
         * argument rather than the mention. The first comma inside the call opens
         * the list; commas inside a nested `strlen(` are skipped by the depth
         * counter. */
        arg = call;
        for (depth = 0; arg < stmt_end; arg++) {
            if (*arg == '(') {
                depth++;
            } else if (*arg == ')') {
                if (depth == 0) {
                    break;
                }
                depth--;
            } else if (*arg == ',' && depth == 1) {
                const char *b = arg + 1;

                while (b < stmt_end && (*b == ' ' || *b == '\n' || *b == '\t' ||
                                         *b == '\r')) {
                    b++;
                }
                if (strncmp(b, "m->params[", 10u) == 0) {
                    TF_CHECK_MSG(0,
                                 "a printf() in msg_verbs.c passes m->params[...] as "
                                 "an argument in its own right. Those are the "
                                 "client's bytes off the parse tree, and a log site "
                                 "that prints one has to be right about what its "
                                 "caller validated -- which is a property of the "
                                 "caller, not of the log line. Route the value through "
                                 "conn_text_logsafe() and report its length and "
                                 "conn_text_bad_count() beside it, per "
                                 "connection.h's Rule 1. This is the rule #134 was "
                                 "filed about: the line that carried a "
                                 "client-supplied <msgtarget> into printf(\"%%s\") "
                                 "unfiltered.");
                }
            }
        }
        at = stmt_end + 1;
    }
}

/* ---------------------------------------------------------------------------
 * THE RULE: EVERY WRITE TO fanout_target_t::name GOES THROUGH ONE STORE
 * ---------------------------------------------------------------------------
 * `fanout_target_t::name` is a target a client named, and it is PRINTED -- at
 * msg_verbs.c's `msg:` observable, at every refusal that names the target, at
 * every reply that echoes it. `fanout_resolve()` used to write it with three bare
 * `memcpy()` calls guarded by a chain of three conditions, and every one of those
 * conditions is a fact about ROUTING ("is this a channel", "does the registry
 * hold that nick", "is that a local user") rather than a fact about RENDERING.
 * The chain works today; the shape is what does not survive a refactor, because
 * the day one guard is loosened -- a channel charset widened, a registry lookup
 * made more permissive, a lenient-accept edit -- the byte is in a struct with
 * nothing between it and a log line.
 *
 * So the validation moved to the STRUCT: `fanout_name_store()` is the only writer
 * of `out->name`, it refuses rather than copies, and it asks
 * `conn_text_display_check()` -- the same walk `valid_nick()` asks for
 * `conn_t::nick` and `conn_realname_check()` asks for `conn_t::realname`, which
 * are the other two fields that are stored and re-rendered into every line their
 * owner sends.
 *
 * What this check asserts is the SHAPE, not the predicate: that the raw stores
 * are gone, that the helper exists, that every call site routes through it, and
 * that the helper asks a predicate at all. A future edit that adds a fourth
 * branch with a fourth `memcpy` therefore fails here rather than passing until
 * somebody reaches the byte from a socket -- which is the whole difference
 * between this check and the sweep's, and the reason the sweep did not find the
 * `nick@server` site in the first place: the audit that named it could not get a
 * control byte through the guard chain either. */
static void check_target_is_validated_at_the_struct(void)
{
    char code[TF_SRC_MAX];
    size_t stores;
    size_t i;

    read_src(code, sizeof code, "src/core/fanout.c");
    squash(code);

    /* THE HELPER EXISTS, and it is not a stub: it must consult a predicate. The
     * predicate's own name is not pinned, because the RIGHT walk is a decision
     * this file should not make twice -- what is asserted is that the store asks
     * SOMETHING before it copies, and that the something is the display walk the
     * two other stored identity fields use. */
    TF_CHECK_MSG(has(code, "static int fanout_name_store("),
                 "fanout.c no longer defines fanout_name_store(). It is the one "
                 "place a byte gets into fanout_target_t::name, and without it the "
                 "safety of that field is back to whichever guard chain a reader "
                 "can reconstruct -- which is the shape the audit named.");
    TF_CHECK_MSG(has(code, "conn_text_display_check( src )") ||
                 has(code, "conn_text_display_check(src)"),
                 "fanout_name_store() no longer asks conn_text_display_check(). "
                 "That walk is the same one valid_nick() asks for conn_t::nick and "
                 "conn_realname_check() asks for conn_t::realname, because all "
                 "three fields are stored and re-rendered into every line their "
                 "owner sends. A store that validates against a different set is a "
                 "second answer to the same question, and this tree has been bitten "
                 "by that three times.");

    /* THE RAW STORES ARE GONE. The count is of `memcpy(out->name ...` rather
     * than of every memcpy in the file, so the store's own copy is the one that
     * has to be the only one: it lives immediately after the predicate, inside
     * the helper, and a second copy anywhere else in the file is a writer that
     * does not go through it. */
    stores = 0u;
    for (i = 0u; code[i] != '\0'; i++) {
        if (strncmp(&code[i], "memcpy( out->name", 17u) == 0 ||
            strncmp(&code[i], "memcpy(out->name", 16u) == 0) {
            stores++;
        }
    }
    TF_CHECK_MSG(stores == 1u,
                 "fanout.c holds %lu memcpy() call(s) into out->name and exactly "
                 "one is allowed: the one inside fanout_name_store(), immediately "
                 "after the predicate. A second one is a writer that does not go "
                 "through the store, and it is the writer a future refactor will "
                 "loosen first.", (unsigned long)stores);

    /* AND IT IS ACTUALLY ASKED, rather than defined and ignored. The resolution
     * function has four branches -- channel, `nick@server` naming this node, the
     * registry's remote pair, and a bare local nick -- and every one of them
     * resolves through the same store, so the call count has to reach all four.
     * The count is a FLOOR for the same reason test_relay_shape.c's is: a new
     * branch that resolves legitimately adds one, and a test that fails on an
     * addition is a test that gets deleted rather than updated. */
    stores = 0u;
    for (i = 0u; code[i] != '\0'; i++) {
        if (strncmp(&code[i], "fanout_name_store( out", 22u) == 0 ||
            strncmp(&code[i], "fanout_name_store(out", 21u) == 0) {
            stores++;
        }
    }
    /* One call per resolution branch, plus the definition itself, plus the call
     * inside the definition is not counted -- the needles above are for calls,
     * and the definition is `static int fanout_name_store(` which the first
     * needle (`fanout_name_store( out`) does not match. */
    TF_CHECK_MSG(stores >= 4u,
                 "fanout_name_store() is called %lu time(s) and fanout_resolve() "
                 "has four resolution branches, each of which must store its "
                 "target through the one store. Fewer means a branch writes "
                 "out->name some other way, and that branch is the one the next "
                 "refactor will loosen.", (unsigned long)stores);
}

int main(void)
{
    check_width_is_derived();
    check_fields_are_arrays();
    check_render_is_three_fields();
    check_no_raw_params_in_printf();
    check_target_is_validated_at_the_struct();

    /* THE FIFTH CHECK HAS SOMETHING TO FIND, and saying so is what stops the
     * "a check that cannot fail is worse than none" failure: `msg_params_printed_
     * raw.py` was written against a file that HAD the violation the fourth check
     * now refuses, and `memcpy_target_printed_raw.py` was written against the one
     * the fifth refuses. A reader who wants to know whether either can pass
     * vacuously can apply those and watch them go red. */
    {
        /* WHAT IS STILL WORTH SAYING AFTER THE FIVE CHECKS, and it is deliberately
         * WEAK, so it is labelled weak here rather than dressed up.
         *
         * These two needles are identifiers and a call name, not string literals,
         * because `tf_read_code()` strips literals and the thing one would most
         * like to assert -- that `msg_refused:` is still in the file -- is
         * therefore invisible to this reader. Reading the file a second time
         * unstripped to look for a log prefix would make the assertion depend on
         * the shape of a printf call site rather than on anything a reader of the
         * protocol cares about, and would go red when somebody reworded a log
         * message for a good reason.
         *
         * So: the file still uses the renderer whose width P1 derives, and the
         * file still uses the log policy P4's rule points at. Both are
         * liveness checks, not correctness checks, and the four above are the
         * correctness ones. */
        char mv[TF_SRC_MAX];

        read_src(mv, sizeof mv, "src/core/msg_verbs.c");

        TF_CHECK_MSG(has(mv, "conn_hostmask("),
                     "msg_verbs.c no longer calls conn_hostmask(). P1 derives a "
                     "width for a renderer this file no longer uses, so the "
                     "unreachability argument it supports no longer describes the "
                     "code -- and the 404 branch it is about may have been removed, "
                     "which is a decision nobody recorded here.");
        TF_CHECK_MSG(has(mv, "conn_text_logsafe("),
                     "msg_verbs.c no longer calls conn_text_logsafe() anywhere. The "
                     "rule above is then enforcing nothing in this file, and every "
                     "log line here prints a client string raw.");
    }

    tf_done("hostmask_reachability");
    return 0;
}
