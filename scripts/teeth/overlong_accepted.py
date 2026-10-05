"""FAULT: OVERLONG accepted -- the bypass vector the canonical check exists for.

Removing only the `E0` arm leaves the ranges accepting `E0` again, so `E0 80 AF` -- an
overlong solidus, which decodes to `/` -- is a legal nickname again. Nothing else in
the tree changes, and nothing about `a-macron` or `nihon` changes.
"""
p = "src/core/connection.c"
s = open(p).read()
old = """    if (u == 0xe0u) {
        if (verdict != NULL && (unsigned char)at[1] < 0xa0u) {
            *verdict = CONN_DISPLAY_UTF8;
            return TEXT_FAULT;
        }
        *need = 2u;
        return TEXT_EMIT;
    }"""
new = """    if (u == 0xe0u) {
        *need = 2u;
        return TEXT_EMIT;
    }"""
assert old in s, "the 0xE0 arm not found"
open(p, "w").write(s.replace(old, new))
