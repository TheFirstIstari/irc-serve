"""FAULT: `CONN_HOSTMASK_MAX` typed back in as a literal.

The unreachability argument #134's comment used to make -- "CONN_HOSTMASK_MAX is
the SUM of the three struct widths, so conn_hostmask() would have to truncate a
string built from those same three widths, which is a compile-time impossibility"
-- rests entirely on the macro being a DERIVATION. Replace it with the number it
happens to equal today (64 + 64 + 128 + 3 = 259) and the argument is still true
today, still false the day a field grows, and nothing in the build says so.

The number is the correct one, which is the point: this fault cannot be caught by
comparing the constant against anything, because the constant is right. It is
caught only by asserting the FORM.

It also goes through a wrong value rather than a non-numeric one so that the tree
still builds and still passes every other test in the suite -- a fault that does not
compile proves nothing, and this file's premise is that a source-level regression
can leave the build perfectly green.
"""
p = "src/core/connection.h"
s = open(p).read()
old = """#define CONN_HOSTMASK_MAX (sizeof(((conn_t *)0)->nick) + \\
                           sizeof(((conn_t *)0)->user) + \\
                           sizeof(((conn_t *)0)->host) + 3u)"""
new = """/* FAULT: the right number, typed in, which stops being the right number the day
 * a field grows. */
#define CONN_HOSTMASK_MAX 259u"""
assert old in s, "the CONN_HOSTMASK_MAX derivation not found"
open(p, "w").write(s.replace(old, new))
