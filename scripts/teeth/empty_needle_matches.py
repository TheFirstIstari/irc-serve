"""FAULT: a zero-length needle reports "found", by DELETING the guard.

The `needle_len == 0` clause is removed rather than weakened, because
`needle_len >= 0` is a tautology and `-Werror` refuses to compile it -- and a fault
that does not compile proves nothing, which is the third time this pass has had to
reshape a fault for that reason.

With the clause gone, `last = hay_len - 0` is `hay_len`, the loop runs, and
`memcmp(..., 0) == 0` succeeds at offset 0, so the function returns `hay`.

Why this one matters more than it looks: a zero-length needle matching EVERYTHING is
not a wrong answer, it is a VACUOUS one. Every assertion written with an empty needle
would then pass for reasons that have nothing to do with what it is asserting, and the
sweep would report a surface clean because it never really made a check.
"""

PATH = "tests/harness/sweep_scan.h"

src = open(PATH).read()
old = """    if (hay == NULL || needle == NULL || needle_len == 0u) {
        return NULL;
    }"""
new = """    if (hay == NULL || needle == NULL) {
        return NULL; /* FAULT: the empty-needle guard is gone */
    }"""
assert old in src, "the empty-needle guard not found"
open(PATH, "w").write(src.replace(old, new))
