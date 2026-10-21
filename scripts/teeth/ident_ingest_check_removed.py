"""FAULT: the IDENT INGEST CHECK REMOVED from handle_user().

`copy_field()` bounds length and tests no byte, so with the `nickreg_ident_ok()`
guard gone `c->user` is whatever the client typed again: `USER <ESC>[2J<ESC>[31m
... <ESC>[0m 0 * :x` stores the bytes, `conn_hostmask()` renders them into the
PREFIX of every line that client sends, and `message_build()` memcpy's the
prefix verbatim with no filter anywhere. Anonymous, pre-registration, no
credential.

The whole branch is DELETED rather than disabled, because `-Werror` makes a
provably-dead branch -- `trunc_user` would then be unused on the else path --
a build error, and a fault that does not compile proves nothing at all. The
deletion is written to leave a one-line else, which is exactly the shape the
tree had before the fix and therefore exactly the shape a reader would
"simplify" back to.

WHAT SHOULD GO RED, and why the two tests are both named:
  * test_ident_injection  -- the co-member's hostmask comes back as
    `:atk!<ESC>[2J...@127.0.0.1 JOIN #IDT` instead of `:atk!@127.0.0.1`, and
    the whole-buffer scan finds the marker on the witness's socket.
  * test_terminal_sweep  -- the STATEFUL stored-ident probe reaches the same
    hostmask on its own surface, so the property is caught twice and neither
    instrument can be quietly deleted to keep the other green.
"""

PATH = "src/core/commands.c"
CLOSE = "\n    }\n"

src = open(PATH).read()

opener = "    if (m->params[0][0] != '\\0' &&\n        nickreg_ident_ok(m->params[0], sizeof c->user) == 0) {"
start = src.index(opener)
end = src.index(CLOSE, start) + len(CLOSE)
# Keep the else arm's body, re-indented two spaces fewer, as a plain statement.
else_start = src.index("    } else {", end)
body_start = end
body_end = src.index(CLOSE, else_start)
body = src[body_start + len("    } else {\n"):body_end]
src = src[:start] + "    " + body.lstrip(" ").lstrip("\n") + src[else_start + len("    } else {\n"):]

open(PATH, "w").write(src)
