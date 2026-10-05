"""FAULT: the echo filter reverted -- the strip call replaced by a copy.

`emit_numeric_ex()` is the one place a numeric's parameters are rendered and all
eleven echoes go through it. Reverting the whole function would be caught by many
tests; the interesting fault is to keep the field bookkeeping and replace the one
call that FILTERS, so that everything still builds, every numeric still renders with
its field in the right position, and the only thing gone is the byte removal.

It replaces the call rather than branching around it because `-Werror` turns a
provably-unreachable branch into a build error, and a fault that does not compile
proves nothing at all.
"""
p = "src/core/reply.c"
s = open(p).read()
old = "        kept = conn_text_strip_wire(arena + used, room, v);"
new = """        /* FAULT: the filter removed, the field bookkeeping kept. */
        kept = strlen(v);
        memcpy(arena + used, v, kept + 1u);"""
assert old in s, "the wire strip call not found"
open(p, "w").write(s.replace(old, new))
