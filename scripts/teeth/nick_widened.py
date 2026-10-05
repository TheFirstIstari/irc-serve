"""FAULT: the nickname check WIDENED to all non-ASCII.

The rule is four exclusions from three ranges, so "accept anything >= 0x80" is a
deletion rather than a rewrite, and it is the mistake this code is most likely to be
"simplified" into: it accepts the Cyrillic, the Greek and every accented character --
and it also accepts `C2 9B`, which is CSI, and every surrogate and overlong sequence
the canonical check refuses.

Both C1 cases are DELETED rather than disabled with a constant, because `-Werror`
makes a provably-dead branch a build error, and a fault that does not compile proves
nothing at all.
"""

PATH = "src/core/connection.c"
CLOSE = "\n    }\n"

src = open(PATH).read()
for opener in ('    if (u == 0xc2u && (unsigned char)at[1] >= 0x80u',
               '    if (u >= 0x80u && u <= 0x9fu) {'):
    start = src.index(opener)
    end = src.index(CLOSE, start) + len(CLOSE)
    src = src[:start] + src[end:]

open(PATH, "w").write(src)