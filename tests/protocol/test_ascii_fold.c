/* test_ascii_fold.c -- the node's ONE ASCII fold (issue #181).
 *
 * Every case-insensitive comparison on the node goes through
 * irc_ascii_fold()/irc_ascii_same() (core/message.h, defined once in
 * core/server.c). This pins the three properties the fold exists for:
 *
 *   1. A-Z folds to a-z, so `BOB` and `bob` -- and `IRC.A` and `irc.a` -- are
 *      one name (2.1, 2.4).
 *   2. The fold is LOCALE-INDEPENDENT. In a Turkish locale tolower('I') is
 *      U+0131 (dotless i), not 'i'; a fold built on tolower() would make two
 *      nodes on differently-configured hosts disagree about whether a
 *      nickname is taken. The locale is set to Turkish here (when the
 *      platform has it) precisely so a future tolower() rewrite fails.
 *   3. Nothing else folds: []\~ stay distinct from {}|^ (005 promises
 *      CASEMAPPING=ascii), and bytes >= 0x80 pass through untouched, so a
 *      UTF-8 nickname is never mangled by comparison.
 */
#include <assert.h>
#include <locale.h>
#include <string.h>

#include "core/message.h"

int main(void)
{
    size_t i;

    /* The Turkish trap first: with a Turkish locale active, a tolower()-built
     * fold turns 'I' into U+0131 instead of 'i'. The locale may be absent on
     * the machine running this; the assertions hold either way, because the
     * fold never consults the locale. */
    (void)setlocale(LC_ALL, "tr_TR.UTF-8");
    assert(irc_ascii_fold('I') == 'i');
    assert(irc_ascii_same("I", "i") != 0);
    assert(irc_ascii_same("IRC.A", "irc.a") != 0);

    /* The whole A-Z range, both directions of use. */
    for (i = 0; i < 26u; i++) {
        char up = (char)('A' + i);
        char lo = (char)('a' + i);

        assert(irc_ascii_fold(up) == lo);
        assert(irc_ascii_fold(lo) == lo);
    }

    /* Everything else passes through: digits, punctuation, NUL-adjacent. */
    assert(irc_ascii_fold('0') == '0');
    assert(irc_ascii_fold('[') == '[');
    assert(irc_ascii_fold('{') == '{');
    assert(irc_ascii_fold('~') == '~');
    assert(irc_ascii_fold('^') == '^');

    /* Bytes >= 0x80 are untouched, so comparison never mangles UTF-8. */
    for (i = 0x80u; i < 0x100u; i++) {
        assert(irc_ascii_fold((char)i) == (char)i);
    }

    /* CASEMAPPING=ascii, not rfc1459: []\~ and {}|^ are NOT equivalent. */
    assert(irc_ascii_same("[b~", "{b^") == 0);
    assert(irc_ascii_same("BOB", "bob") != 0);
    assert(irc_ascii_same("Bob", "bOB") != 0);

    /* Lengths still matter, and NULL is never equal to anything. */
    assert(irc_ascii_same("a", "ab") == 0);
    assert(irc_ascii_same("", "") != 0);
    assert(irc_ascii_same(NULL, "a") == 0);
    assert(irc_ascii_same("a", NULL) == 0);
    assert(irc_ascii_same(NULL, NULL) == 0);

    return 0;
}
