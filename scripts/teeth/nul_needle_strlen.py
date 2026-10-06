"""FAULT: a needle containing NUL is handled with `strlen`.

The comparison becomes `memcmp(hay + i, needle, strlen(needle))` while `last` is still
computed from the real `needle_len`, so the needle is silently SHORTENED to its first
run of non-NUL bytes.

This is the fault the explicit length parameter exists to prevent, and it is the
opposite direction from the other two: the answer is too PERMISSIVE, not too strict, so
nothing about the sweeps goes red on it -- a truncated needle matches a prefix. It is
caught by the self-test's mismatching-NUL case, and it is listed here because a
shortened needle is a false NEGATIVE waiting for the byte that distinguishes two
candidates.

The length is honoured explicitly at every other site in the function too, so this fault
is a one-token change that a reader would not notice without the reason written next to
it -- which is the whole reason the reason is next to it.
"""

PATH = "tests/harness/sweep_scan.h"

src = open(PATH).read()
old = "        if (hay[i] == needle[0] && memcmp(hay + i, needle, needle_len) == 0) {"
new = ("        if (hay[i] == needle[0] &&\n"
       "            memcmp(hay + i, needle, strlen(needle)) == 0) { /* FAULT */")
assert old in src, "the comparison not found"
open(PATH, "w").write(src.replace(old, new))