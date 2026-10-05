"""FAULT: the nickname check NARROWED to a bare byte range.

The mirror of the widening fault, and the more likely one: a reviewer sees "refuse
0x80-0x9F" -- which is how the rule was written down before anyone noticed that `a-
macron` is C4 81 -- and writes it. This fault must make the accented character
INVALID and nothing else, which is what makes it a test of the SEQUENCE state rather
than of a set.
"""
p = "src/core/connection.c"
s = open(p).read()
old = """    if (*need > 0u) {
        if (u >= 0x80u && u <= 0xbfu) {"""
new = """    if (*need > 0u) {
        if (u >= 0x80u && u <= 0x9fu) {"""
assert old in s, "the continuation-byte range not found"
open(p, "w").write(s.replace(old, new))
