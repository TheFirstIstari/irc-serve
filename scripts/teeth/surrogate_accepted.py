"""FAULT: SURROGATE accepted -- U+D800 is not a character and has no UTF-8 encoding.

Removing only the `ED` arm leaves `ED A0 80` a well-shaped three-byte sequence, which
is exactly what it looks like to a validator that checks shape rather than
canonicity. `ED A0 80` is how UTF-8 says "this is not a character".
"""
p = "src/core/connection.c"
s = open(p).read()
old = """    if (u == 0xedu) {
        if (verdict != NULL && (unsigned char)at[1] > 0x9fu) {
            *verdict = CONN_DISPLAY_UTF8;
            return TEXT_FAULT;
        }
        *need = 2u;
        return TEXT_EMIT;
    }"""
new = """    if (u == 0xedu) {
        *need = 2u;
        return TEXT_EMIT;
    }"""
assert old in s, "the 0xED arm not found"
open(p, "w").write(s.replace(old, new))
