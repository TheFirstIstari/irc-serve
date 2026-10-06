"""FAULT: the bounded search is off by ONE AT THE HAYSTACK END.

`last = hay_len - needle_len` becomes `last = hay_len`, so an occurrence may START at
offset `hay_len` -- one byte past the declared range -- and the final `memcmp()` reads
`needle_len - 1` bytes past the end of it.

This is the specific failure the primitive exists to prevent, which is why it gets its
own fault rather than sharing one with the other two. Both other faults change an
ANSWER; this one changes a BOUND, and a search that reads outside what it was given
cannot be trusted even when the value it returns happens to be right.

Every one of the thirteen local gate cells passes with this fault in, because the bytes
past the end are still inside the process on every ordinary run and the answer only
differs when they happen to match.
"""

PATH = "tests/harness/sweep_scan.h"

src = open(PATH).read()
old = "    last = hay_len - needle_len;"
new = "    last = hay_len; /* FAULT: one byte too far */"
assert old in src, "the bound not found"
open(PATH, "w").write(src.replace(old, new))