"""FAULT: the peer sweep's rule removed from ONE site.

`scripts/check-peer-log-sites.py` says: no `m->params[...]` and no `m->command`
reaches a `[observable]` printf in `src/federation/` as a `%s` argument.

This fault takes `apply_nick()`'s refusal line back to the shape #135 filed --
`(m->nparams > 0) ? m->params[0] : "?"` printed with a bare `printf` -- so BOTH
instruments have something to catch:

  * `check-peer-log-sites.py` reports the `m->params[0]` argument, and
  * `test_burst_malformed_log` drives an `SBURSTN` with a marker byte in that
    nickname over a real handshake and finds the byte in the node's own stdout.

The test is named in `scripts/teeth.sh`'s fault list even though it is not a
`run_fault` target in the usual sense: the fault here is a SOURCE class, and the
sweep is the check for it. Running it by hand is part of the teeth claim and the
report should say so.

Note that `apply_nick()`'s line prints the nickname on the branch where
`valid_nick()` has NOT run, so this is not a "documented unreachable" case the way
#134's was -- it is reachable with one parameter, which is why the fault's docstring
does not have to argue anything.
"""
p = "src/federation/burst.c"
s = open(p).read()
old = '''            fed_obs("[observable] fed_malformed: fd=%d command=SBURSTN nick=%s "
                    "nick_len=%zu nick_bad_bytes=%zu\\n",
                    link->fd, raw, strlen(raw), conn_text_bad_count(raw));'''
new = '''            /* FAULT: the peer's nickname into printf("%s"), unfiltered. */
            printf("[observable] fed_malformed: fd=%d command=SBURSTN nick=%s\\n",
                   link->fd, raw);'''
assert old in s, "apply_nick's filtered malformed line not found"
open(p, "w").write(s.replace(old, new))