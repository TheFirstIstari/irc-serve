/* test_nick_policy.c -- 2.1's rename-the-loser DECISION, as the pure total order
 * it is documented to be.
 *
 * docs/SERVER_DESIGN.md 2.1 ("Two servers may legitimately hold the same nick, so
 * the loser must be told on the wire, not silently renamed locally") and 8.
 *
 * ---------------------------------------------------------------------------
 * WHY A UNIT TEST, WHEN THE POLICY'S CLAIM IS A MESH
 * ---------------------------------------------------------------------------
 * The claim "a mesh of N nodes converges on one name per user" is an integration
 * claim, and tests/integration/test_nick_duplicate.c asserts it by building a
 * duplicate and watching both ends. What that test CANNOT cheaply assert is the
 * property the convergence argument rests on: that the comparison is a TOTAL
 * ORDER.
 *
 * The argument is four words long -- "the same pair of names yields the same
 * winner on every node" -- and it is false in more ways than it first appears.
 * A comparison that is merely "usually consistent" produces a mesh that renames a
 * user on one side and renames BACK on the other, and the observable is a pair of
 * users ping-ponging for ever with every node believing it acted correctly. So the
 * properties below are asserted directly, as the three axioms a total order needs
 * and as the two 2.1-specific rules around them:
 *
 *   1. TOTAL      every pair gets an answer, and the answer is a direction
 *   2. ANTISYMMETRIC   exactly one of (a,b) and (b,a) says "the local is renamed"
 *   3. TRANSITIVE     if b beats c and c beats d, then b beats d
 *   4. FOLDS         case does not decide anything, because 2.4's grammar and
 *                    2.1's are both case-insensitive and a comparison that
 *                    depended on case would let a peer choose its winner by
 *                    SPELLING ITS OWN NAME
 *   5. NO SHARED CLOCK   the two callers do not know each other's uptime, so a
 *                    comparison that needed one could not be evaluated by both
 *
 * Rule 4 is the one that has a security shape to it, and it is why the function
 * takes no third argument: a node that could make its own name sort first would be
 * a node that could make itself un-renameable.
 *
 * ---------------------------------------------------------------------------
 * WHY THE PREFIX CASES ARE HERE AND NOT LEFT IMPLICIT
 * ---------------------------------------------------------------------------
 * Server names are "letters, digits, '-' and '.'" (2.4), so `irc.b` and `irc.b1`
 * are both legal and one is a PREFIX of the other. A byte loop that compares until
 * a mismatch and treats "ran out of bytes" as a tie would return "no loser" for
 * that pair -- and then BOTH nodes would keep the name, which is the
 * "user-visible and undefined" state 2.1 names. The cases at the bottom are the
 * only thing standing between that and a shipped binary, because no integration
 * test can be written against a pair of server names that do not both have to be
 * configured.
 *
 * NO FIXED sleep() AND NO SOCKETS: this file opens nothing and forks nothing. It
 * links irc_core for the one function, exactly as the other two tests in this
 * directory do.
 */
#include <stdio.h>
#include <string.h>

#include "federation/nickreg.h"

static int failures;

static void check(int ok, const char *what, const char *a, const char *b)
{
    if (ok) {
        return;
    }
    failures++;
    printf("FAILED: %s (a=\"%s\" b=\"%s\")\n", what, a, b);
}

/* The two directions, and the axiom they are the axiom for. `loses(a, b)` is
 * "fed_nickreg_local_loses(a, b) != 0" -- A is the LOCAL holder and B the remote
 * one, and the function answers "must A be renamed?". */
static int loses(const char *a, const char *b)
{
    return fed_nickreg_local_loses(a, b) != 0;
}

static void case_total_and_antisymmetric(void)
{
    static const char *const pairs[][2] = {
        { "irc.a", "irc.b" }, { "irc.b", "irc.a" },
        { "irc.z", "irc.b" }, { "irc.b", "irc.z" },
        { "irc.b", "irc.b1" }, { "irc.b1", "irc.b" },
        { "a",    "b"    }, { "b",    "a"    },
        { "node-1", "node-2" }, { "node-2", "node-1" },
        { "irc.b", "irc.b1" }, { "irc.b1", "irc.b" },
    };

    for (size_t i = 0; i < sizeof pairs / sizeof pairs[0]; i++) {
        const char *a = pairs[i][0];
        const char *b = pairs[i][1];
        int ab = loses(a, b);
        int ba = loses(b, a);

        /* TOTAL, AND NO TIE: the function answers 0 or 1, and the assertion is
         * that the two directions of a pair never agree -- which is the statement
         * that a pair of DISTINCT names always names a winner. A self-pair is
         * excluded here on purpose: `loses(x, x)` is 0 in both directions by
         * construction, and case_reflexive() asserts that separately, because "a
         * name does not lose to itself" and "two names never tie" are different
         * claims and folding them together would hide a comparison that returned 0
         * for a real pair. */
        check(ab != ba,
              "exactly one direction of a pair must name a loser; a tie means both "
              "nodes keep the name and 2.1's ambiguity survives",
              a, b);
    }
}

static void case_reflexive(void)
{
    /* A NAME NEVER LOSES TO ITSELF, and the reason is convergence rather than
     * tidiness: a node whose own name compared equal to itself would decide it was
     * the loser against its own entry, and the SJOIN for one of its own members
     * produces exactly such an entry. So this is not a synthetic case -- it is the
     * one the live path hits on every single SJOIN this node forwards. */
    check(loses("irc.a", "irc.a") == 0,
          "a server must never lose to its own name, or every SJOIN for its own "
          "member would rename somebody",
          "irc.a", "irc.a");
    check(loses("", "") == 0, "two empty names must not name a loser", "", "");
}

static void case_empty_remote_never_wins(void)
{
    /* AN ENTRY WITH NO HOLDER CANNOT OUTRANK A NAME, and the reason is that 4.3's
     * SJOIN carries no server field: an entry learned from one has an empty
     * holder. Treating that as a competing claim would let a peer rename a user by
     * sending an SJOIN with no server at all -- a capability no message in 4.3 is
     * supposed to carry, and one no design has proposed. */
    check(loses("irc.z", "") == 0,
          "a remote holder with no name must not be able to make the local holder "
          "lose, or a peer could rename a user by omitting a field",
          "irc.z", "");
    check(loses("", "irc.z") == 0,
          "a local name with no name must not lose either, or a node with an "
          "unconfigured name would rename every user it has",
          "", "irc.z");
}

static void case_folds(void)
{
    /* CASE DECIDES NOTHING, in either direction, and the reason has a security
     * shape: 2.4's server-name grammar and 2.1's nickname charset are both
     * case-insensitive, so `IRC.A` and `irc.a` are the same server. A comparison
     * that read case as data would let a node choose which of two peers it loses
     * to by SPELLING ITS OWN NAME, and there is nothing on the wire that would
     * catch it -- both spellings pass 2.4's grammar. */
    check(loses("irc.Z", "irc.b") == loses("irc.z", "irc.b"),
          "an upper-case local name must decide the same way as a lower-case one",
          "irc.Z", "irc.b");
    check(loses("irc.b", "IRC.Z") == loses("irc.b", "irc.z"),
          "an upper-case remote name must decide the same way as a lower-case one",
          "irc.b", "IRC.Z");
    check(loses("IRC.Z", "IRC.B") == loses("irc.z", "irc.b"),
          "both sides upper-cased must decide the same way as both lower-cased",
          "IRC.Z", "IRC.B");
}

static void case_transitive(void)
{
    /* THREE NAMES, and the direction of the rule first, because getting it backwards
     * is the easy mistake and it would make every assertion below pass for the
     * wrong reason: THE GREATER NAME LOSES, so of `b` and `c` it is `c` that is
     * renamed, not `b`. 2.1 does not say which of two users is right, so this
     * implementation picked "the lexicographically greater server name gives way",
     * and the property being asserted is that the choice is CONSISTENT -- not that
     * it is this particular choice. */
    check(loses("irc.c", "irc.b") != 0,
          "the greater of two names must be the one renamed: 'c' > 'b'", "irc.c",
          "irc.b");
    check(loses("irc.b", "irc.c") == 0,
          "the smaller of two names must keep the nick: 'b' < 'c'", "irc.b",
          "irc.c");

    /* TRANSITIVE, which is the property the convergence argument actually needs.
     * Three nodes agreeing pairwise is not enough: the ordering has to be
     * consistent ACROSS pairs, or node A can believe d loses to b while node D
     * believes b loses to d -- and the two then disagree about a name neither of
     * them holds, with no line on the wire to settle it. */
    check(loses("irc.d", "irc.c") != 0, "d must lose to c", "irc.d", "irc.c");
    check(loses("irc.d", "irc.b") != 0,
          "d must lose to b when d loses to c and c loses to b; a comparison "
          "that is consistent per pair but not across pairs is what makes two "
          "nodes disagree about a name",
          "irc.d", "irc.b");
    check(loses("irc.b", "irc.d") == 0, "b must keep what d gives up", "irc.b",
          "irc.d");
}

static void case_prefix_is_an_order(void)
{
    /* THE PREFIX CASES, and they are the ones no integration test can reach. Two
     * legal 2.4 server names where one is a strict prefix of the other, so a byte
     * loop runs out of bytes before it finds a mismatch. The shorter name is the
     * SMALLER one, so it keeps the nick and the longer one is renamed -- and the
     * mirror pair has to agree, or a node would rename the user on one node and
     * keep it on the other, which is the ping-pong this whole policy exists to
     * end. */
    check(loses("irc.b", "irc.b1") == 0,
          "a name that is a strict prefix of the other is the smaller name and "
          "keeps the nick",
          "irc.b", "irc.b1");
    check(loses("irc.b1", "irc.b") != 0,
          "the longer of a prefix pair is renamed, and this is the mirror of the "
          "case above rather than an independent claim",
          "irc.b1", "irc.b");
    check(loses("a", "ab") == 0, "a one-byte name is the smaller of a prefix pair",
          "a", "ab");
    check(loses("ab", "a") != 0, "and the mirror of that one too", "ab", "a");
    /* AND THE ORDER COMES FROM THE BYTES, INCLUDING WHERE A BYTE SITS AGAINST THE
     * TERMINATOR. '1' is 0x31 and '-' is 0x2d and the NUL the loop substitutes a
     * space for is above every legal name byte, so `irc.b1` and `irc.b-x` are BOTH
     * greater than `irc.b` and both are renamed -- for different reasons, one by
     * the prefix arm and one by a byte comparison, and a comparison that treated
     * the terminator as "smallest" would decide the second pair the other way. */
    check(loses("irc.b-x", "irc.b") != 0,
          "a byte above the terminator sentinel must make the local name the "
          "greater one: '-' is 0x2d and the sentinel is above every legal name "
          "byte",
          "irc.b-x", "irc.b");
    /* AND THE PREFIX ARM IS FOLDED, so a peer cannot escape a rename by spelling
     * its own name in a different case -- which is the same property case_folds()
     * states about mismatching bytes, applied to the terminator. */
    check(loses("irc.B1", "irc.b") != 0,
          "the prefix arm must fold case, or `irc.B1` and `irc.b1` would be two "
          "different users to 2.1 and one name to 2.4",
          "irc.B1", "irc.b");
}

int main(void)
{
    case_total_and_antisymmetric();
    case_reflexive();
    case_empty_remote_never_wins();
    case_folds();
    case_transitive();
    case_prefix_is_an_order();

    if (failures != 0) {
        printf("%d nick-policy check(s) failed\n", failures);
        return 1;
    }
    printf("ok: nick_policy\n");
    return 0;
}
