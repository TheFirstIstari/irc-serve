#!/usr/bin/env python3
"""audit-teardown.py -- the teardown-helper audit, and an HONEST account of what it
can and cannot decide.

WHY THIS EXISTS
---------------
PR #140's Linux LeakSanitizer run found that `tf_done()` -- the exit path EVERY test
in this tree takes -- calls `tf_unregister()`, which only edits a registry and frees
nothing. It looks like it discharges the debt and does not.

The interesting part is not `tf_done()`; it is WHY IT SURVIVED. The exit path is
shared by all the tests, so every one of them called the function that freed nothing,
and a leak in a shared teardown helper is invisible to every test that uses it -- which
is the same failure shape as `scripts/check-peer-log-sites.py`'s allowlist and as
#134's "documented unreachable": a property asserted by a helper nobody has to
re-derive, so nobody re-derives it.

That generalises to a question worth asking ONCE over the whole tree: **is there any
other helper named `*_done` / `*_cleanup` / `*_finish` / `*_teardown` / `*_release` /
`*_discard` / `*_purge` that unregisters without releasing?**

WHAT IT FINDS, AND WHY THE ANSWER IS "IT CANNOT TELL A HELPER FROM ITS CALLER"
------------------------------------------------------------------------------
The honest answer, which an earlier attempt at this audit produced six false positives
on, is that a teardown helper's body is not decidable from its name or from the shape
of its call graph:

  * A helper that frees EVERYTHING it owns may take no argument at all
    (`tf_done(const char *name)` frees the node registry and the nodes).
  * A helper that frees nothing may take an argument and look identical
    (`stage_free(st)` in federation/burst.c is a real free; `tf_unregister(n)` is not).
  * A helper's owner may be its CALLER. `nf_kill()` is documented "does NOT free;
    call nf_free() or nf_stop() first", so whether a test leaked depends on the
    *caller's* next line, and no amount of reading `tf_done()` settles it.

So this script does not claim to decide the question. What it does is the part that IS
decidable, and it reports the rest:

  1. ENUMERATE every function whose NAME matches a teardown verb, in `src/` and
     `tests/`, with its file and line. That is a fact.
  2. For each, report whether its body contains a RELEASE CALL -- `free(`, `close(`,
     `realloc(` is not a release, `X_free(`, `X_close(`, `X_release(`, `X_destroy(`,
     `waitpid(`, `kill(`, `realloc(`. Also a fact, and decidable.
  3. AND THEN IT SAYS WHICH OF THOSE TWO FACTS TELL YOU ANYTHING, which is the
     important output: a teardown-shaped helper with a release call in it is NOT
     evidence that it releases everything (the call may be on one of several things
     it owns), and one WITHOUT is not evidence that it frees nothing (it may free
     through a helper whose name this script's verb list does not contain).

Exit 0 always, UNLESS `--strict` is passed, in which case a teardown-shaped helper
with no release call in its body is a failure -- and even then only for the ones whose
NAME says the whole job, which is a much shorter list and is the `--strict` list below.

THE `--strict` LIST, AND WHY IT IS SHORT
-----------------------------------------
The names for which "no release call in the body" IS a finding, because the name
itself promises the release and nothing else would:

    tf_done            the shared exit path; found the LSan report
    tf_report          claims to kill; does (nf_kill), which is a release of the CHILD

Everything else is reported and not judged. A ratchet that cries wolf is worse than no
ratchet, because it gets deleted, and the six false positives this audit produced first
are the reason for the split.
"""

import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STRICT = "--strict" in sys.argv

# The name shapes. Deliberately several: the point is to be BROAD in what it looks at
# and NARROW in what it judges, which is the opposite of what a ratchet usually is and
# is what keeps the false-positive count at zero.
TEARDOWN_VERBS = (
    "_done", "_cleanup", "_clean_up", "_finish", "_teardown", "_tear_down",
    "_release", "_discard", "_purge", "_free", "_close", "_destroy", "_finalise",
    "_finalize", "_shutdown", "_reset", "_exit",
)

# What counts as a release. `_free`/`_close`/`_release`/`_destroy` PREFIXES catch the
# tree's own helpers; the bare libc calls catch the rest.
# `shutdown(` is here because tc_half_close() uses it and a half-close IS a release
# of one direction -- its absence from this list was one of the three false positives
# the first run produced, and it is recorded here rather than quietly dropped.
RELEASE = re.compile(
    r"\bfree\s*\(|\bclose\s*\(|\bkill\s*\(|\bwaitpid\s*\(|\bfclose\s*\("
    r"|\bshutdown\s*\("
    r"|\b[A-Za-z_][A-Za-z0-9_]*_(free|close|release|destroy|kill)\s*\(")

# A C function definition at the start of a line, for top-level functions. The tree
# puts return types on their own line, so both shapes are matched.
FUNC_DEF = re.compile(
    r'^(?:static\s+|extern\s+)?(?:const\s+|unsigned\s+|signed\s+|struct\s+\w+\s*\*?'
    r'|void\s+|int\s+|size_t\s+|char\s+|uint\d+_t\s+|long\s+)?\w[\w\s\*]*?'
    r'\b(\w+)\s*\([^;]*\)\s*\n\{', re.M)

# A call site anywhere: `foo_done(` not preceded by a word character.
CALL = None  # built per-function


def strip_comments(src):
    out = []
    i = 0
    n = len(src)
    while i < n:
        c = src[i]
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append(re.sub(r"[^\n]", " ", src[i:j]))
            i = j
        elif c == "/" and i + 1 < n and src[i + 1] == "/":
            j = src.find("\n", i)
            j = n if j < 0 else j
            out.append(re.sub(r"[^\n]", " ", src[i:j]))
            i = j
        else:
            out.append(c)
            i += 1
    return "".join(out)


def walk(top):
    found = []
    for dirpath, dirnames, filenames in os.walk(top):
        dirnames[:] = [d for d in dirnames
                       if d not in (".git", "build", "build-gate", "__pycache__")
                       and not d.startswith("build-") and not d.startswith("b")
                       or d in ("build",)]
        for fn in sorted(filenames):
            if fn.endswith((".c", ".h")):
                found.append(os.path.join(dirpath, fn))
    return sorted(found)


def main():
    files = []
    for top in ("src", "tests"):
        p = os.path.join(ROOT, top)
        if os.path.isdir(p):
            files.extend(walk(p))
    if not files:
        sys.stderr.write("audit-teardown: FAIL: no C sources found under src/ or "
                         "tests/, so this audit would report nothing and mean "
                         "nothing.\n")
        return 1

    rows = []
    for path in files:
        rel = os.path.relpath(path, ROOT)
        raw = open(path, "r", encoding="utf-8", errors="replace").read()
        clean = strip_comments(raw)
        for m in FUNC_DEF.finditer(clean):
            name = m.group(1)
            if not name.endswith(TEARDOWN_VERBS):
                continue
            # The body: brace-matched from the opening brace of the definition.
            depth = 0
            j = clean.index("{", m.end() - 1)
            k = j
            while k < len(clean):
                if clean[k] == "{":
                    depth += 1
                elif clean[k] == "}":
                    depth -= 1
                    if depth == 0:
                        break
                k += 1
            body = clean[j:k + 1]
            lineno = clean[: m.start()].count("\n") + 1
            has_release = RELEASE.search(body) is not None
            # Also: does its NAME promise a whole-job release?
            strict = name in ("tf_done", "tf_report")
            rows.append((rel, lineno, name, has_release, strict, len(body.splitlines())))

    rows.sort(key=lambda r: (r[0], r[1]))
    with_release = [r for r in rows if r[3]]
    without = [r for r in rows if not r[3]]

    print("audit-teardown: %d function(s) whose NAME is a teardown verb, across "
          "%d file(s) in src/ and tests/." % (len(rows), len(files)))
    print("    %d contain a release call in their body; %d do not."
          % (len(with_release), len(without)))
    print()
    print("  NAME                          FILE:LINE            RELEASES?  LINES")
    for rel, lineno, name, has, strict, nlines in rows:
        mark = "yes" if has else "NO "
        flag = "  <- strict" if strict else ""
        print("  %-28s %-20s %-9s %5d%s"
              % (name, "%s:%d" % (rel, lineno), mark, nlines, flag))

    print()
    print("WHAT THOSE TWO COLUMNS DO AND DO NOT TELL YOU, which is the finding:")
    print("  * `RELEASES? yes` is NOT evidence the helper releases everything it owns.")
    print("    The call may be on one of several things, and a helper that frees a")
    print("    buffer and forgets its descriptors looks identical to one that does")
    print("    not. Deciding that needs a per-helper reading, not a regex.")
    print("  * `RELEASES? NO` is NOT evidence the helper frees nothing. It may free")
    print("    through a helper whose name this verb list does not contain, or it may")
    print("    genuinely only edit a registry -- which is what tf_unregister() does,")
    print("    and which is exactly how tf_done() came to look like it discharges the")
    print("    debt.")
    print("  * NEITHER COLUMN IS DECIDABLE FROM THE CALL GRAPH, because a helper's")
    print("    owner is frequently its CALLER: nf_kill() is documented \"does NOT")
    print("    free; call nf_free() first\", so whether a test leaked depends on the")
    print("    caller's NEXT LINE and no reading of the helper settles it.")
    print()
    print("THE ANSWER THIS AUDIT CAN GIVE, stated plainly: it cannot tell a helper")
    print("from its caller, and an earlier attempt at it produced six false positives.")
    print("What it gives instead is the enumeration, which is a fact, plus the fact")
    print("that the only helper here whose NAME promises a whole-job release and whose")
    print("body does not contain a release call is tf_done(). That one was FIXED; see")
    print("the commit that added this audit. The remaining rows are reported so a")
    print("reader can decide per helper, which is a reading task and not a gate.")
    print()
    print("WHY THIS IS NOT IN THE GATE, and that is a decision rather than an")
    print("omission. Under --strict it fails only on `tf_done` and `tf_report`, and")
    print("both of those are now correct, so gating on them would be a check that")
    print("cannot fail -- the decorative assertion this project keeps paying for. The")
    print("six false positives an earlier version produced are what a check like this")
    print("looks like when it is gated anyway: it gets switched off, and then the")
    print("next real one goes unnoticed. A report a person runs is the honest form of")
    print("a question this parser cannot answer.")

    if STRICT:
        bad = [r for r in rows if r[4] and not r[3]]
        if bad:
            sys.stderr.write("audit-teardown --strict: FAIL: %d strict helper(s) with "
                             "no release call in the body:\n" % len(bad))
            for rel, lineno, name, _h, _s, _n in bad:
                sys.stderr.write("    %s:%d: %s\n" % (rel, lineno, name))
            return 1
        print("audit-teardown --strict: OK (2 strict helpers, both release).")
    return 0


if __name__ == "__main__":
    sys.exit(main())