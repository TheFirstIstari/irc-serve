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

THE SECOND RULE, ADDED AFTER THE REAL LEAK, AND ITS LIMIT IS THE POINT
---------------------------------------------------------------------
#134's test read a source through `tf_read_code()` behind a one-line `read_src()`
wrapper, and the function that used the wrapper forgot the `free()`. Linux's
LeakSanitizer reported it as `Direct leak of 65536 byte(s) in 1 object(s)` -- one
object, which is `tf_read_code()`'s initial `cap`, so the trace names the HARNESS and
not the test.

That is the first rule's stated limitation arriving as a real defect rather than as a
caveat: the obligation had left the harness through the wrapper, so no reading of the
harness could have found it and no sweep of the harness's own call sites could see it
either -- the caller of the wrapper is not a caller of the harness.

RULE 2 IS THEREFORE ABOUT ACQUIRE-WITHOUT-RELEASE **IN THE SAME FUNCTION**, and it is
gated:

    var = <one of tf_read_code( strdup( strndup( malloc( calloc( )>
        => var must be the operand of a free() in the SAME function

WHAT IT DOES NOT SEE, stated here rather than discovered later: **it does not see
through a wrapper.** The leak it was written for went through one, so rule 2 would not
have caught it as shipped -- which is exactly why the FIX was to remove the
possibility rather than to add the rule. `test_hostmask_reachability.c`'s `read_src()`
now takes a CALLER-PROVIDED buffer and owns nothing, so there is no pointer to lose;
the other 19 direct `tf_read_code()` sites pair correctly and were never at risk.
`realloc` is EXCLUDED on purpose: it frees the old block itself, so a `p = realloc(p,
n)` needs no separate `free()` and flagging it would be a false positive on correct
code.

THE HONEST SUMMARY OF THE TWO RULES: rule 1 asks "does this teardown-shaped helper
release anything", rule 2 asks "is this pointer released where it was acquired". Both
are decidable from the text. Neither can answer "was the right thing acquired on this
path at all", which is the question a leak check actually asks and the reason Linux CI
remains the only oracle for the thing itself.

THE `--strict` LIST FOR RULE 1, AND WHY IT IS SHORT
--------------------------------------------------
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

# A DELIBERATE leak, declared at the point of the leak. Three groups: the keyword, the
# owning pointer's NAME, and the reason. All three required, and the reason must be at
# least eight characters, because the whole value of this exemption is that a reader can
# see WHICH allocation and WHY without finding this rule.
#   block = malloc(n);  /* audit-teardown: DELIBERATE LEAK block -- this file exists to leak */
# The name is in the marker rather than implied by its position because the marker sits
# on the statement that DROPS the pointer, which is several lines after the malloc: a
# marker with no name cannot tell two acquisitions in one function apart.
DELIBERATE_LEAK = re.compile(
    r"audit-teardown:\s*DELIBERATE\s+LEAK\s+([A-Za-z_]\w*)[^\n]*?--\s*([^\n*]{8,})")

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

# RULE 2: the acquire shapes whose RESULT is heap the caller owns. Narrow on purpose --
# a list that grew to "anything named *_read" would flag a helper that returns an
# int, and a check that flags correct code is the six-false-positives failure again.
# `realloc` is absent because it releases the block it replaces.
# NOT anchored to the start of a line: this tree indents assignments and wraps them
# across lines, and a needle that only matched one of those layouts would report
# clean on the majority of the code it exists to check. The `= ACQUIRE(` shape is
# specific enough on its own -- a comparison (`==`) or a compound assignment cannot
# match it, because `==` is not `= ` and `+=` is not `=`.
ACQUIRE = re.compile(
    r"\b(\w+)\s*=\s*(?:tf_read_code|strdup|strndup|malloc|calloc)\s*\(")

FREE = re.compile(r"\bfree\s*\(\s*(?:&|\(\s*\w+\s*\*\s*\)\s*)?")

# A C function definition, for NAMING the enumeration. Not used for body boundaries --
# see `top_level_bodies()` for why, and that is the third version of this and the
# first two were wrong.
FUNC_DEF = re.compile(
    r'^(?:static\s+|extern\s+)?(?:const\s+|unsigned\s+|signed\s+|struct\s+\w+\s*\*?'
    r'|void\s+|int\s+|size_t\s+|char\s+|uint\d+_t\s+|long\s+)?\w[\w\s\*]*?'
    r'\b(\w+)\s*\([^;]*\)\s*\n\{', re.M)

# TOP-LEVEL FUNCTION BODIES, and this is the version that is right.
#
# The tree indents EVERY nested brace -- an `if` body, a loop body, a compound
# literal, an initialiser -- and opens a function body at column 0. So a `{` at the
# start of a line with nothing before it IS a function body, and brace-matching from
# it gives the whole body without needing to parse the signature at all.
#
# THE TWO VERSIONS THIS REPLACES, and both reported three FALSE POSITIVES on the
# shipped tree by ending a "function body" before the `free()` that was really there:
#   * matching definitions by signature -- `FUNC_DEF` does not match every shape this
#     tree writes, and one unmatched definition means the next match's brace count
#     is taken from the wrong place;
#   * a hand-rolled "same function" scan.
# A rule built on a boundary this script cannot find reliably is a rule that flags
# correct code, and a check that flags correct code gets deleted.
def top_level_body_ranges(clean):
    """The (first_line, last_line) of every top-level body, in the SAME order as
    top_level_bodies() -- which is why this exists at all.

    strip_comments() BLANKS every comment, keeping byte offsets and line breaks. That is
    what makes the parser safe, and it is also why the deliberate-leak marker could not
    be found in the cleaned body: the marker IS a comment, so by the time rule 2 looks
    for it there is nothing there. An exemption that can never fire is not an
    exemption, and this audit would have been green for a reason nobody could see.

    So the ranges are computed from the same CLEANED text the parser uses -- so the
    line numbering cannot drift from it -- and the marker is then looked for in the
    RAW lines. Offsets survive stripping, so `body_end - body_start` in cleaned bytes
    is exactly the raw text of the same span.
    """
    ranges = []
    lines = clean.split("\n")
    offs = []
    off = 0
    for ln in lines:
        offs.append(off)
        off += len(ln) + 1
    for i, ln in enumerate(lines):
        if not ln.startswith("{"):
            continue
        start = offs[i]
        depth = 0
        j = start
        while j < len(clean):
            if clean[j] == "{":
                depth += 1
            elif clean[j] == "}":
                depth -= 1
                if depth == 0:
                    ranges.append((i + 1, i + 1 + clean[start:j].count("\n")))
                    break
            j += 1
    return ranges


def top_level_bodies(clean):
    bodies = []
    lines = clean.split("\n")
    offs = []
    off = 0
    for ln in lines:
        offs.append(off)
        off += len(ln) + 1
    for i, ln in enumerate(lines):
        if not ln.startswith("{"):
            continue
        start = offs[i]
        depth = 0
        j = start
        while j < len(clean):
            if clean[j] == "{":
                depth += 1
            elif clean[j] == "}":
                depth -= 1
                if depth == 0:
                    bodies.append((i + 1, clean[start:j + 1]))
                    break
            j += 1
    return bodies

# A call site anywhere: `foo_done(` not preceded by a word character.
CALL = None  # built per-function


def strip_comments(src):
    """Blank comments AND string/character literals, keeping every byte offset.

    WHY LITERALS ARE BLANKED HERE, and it is a bug this script had twice.

    `top_level_bodies()` brace-matches to find function bodies, and a brace inside a
    STRING LITERAL unbalances the count. `tests/integration/test_disconnect_nick.c`
    has `fn_end = strstr(fn, "\n}\n");` -- a literal `}` at line 384 -- and naive
    matching ended `main()`'s body at line 412 instead of 443, so the `free(code)` at
    line 431 fell outside the "function" and rule 2 reported two false positives on
    correct code. The function-scoped rule on a signature-matching boundary had already
    reported three. Two wrong versions, both for the same reason: the parser was
    counting braces that were not syntax.

    WHY COMMENTS ARE BLANKED, which is the reason `check-portability.py` strips before
    it matches: this check's own argument list and docstring name `m->params[...]` and
    `m->command` many times, and a checker that matched itself would be a checker that
    could only ever fail.

    WHY SPACES AND NOT REMOVAL, for both: every byte offset has to survive, so a
    reported line number refers to the real file.
    """
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
        elif c in "\"'":
            q = c
            j = i + 1
            while j < n:
                if src[j] == "\\":
                    j += 2
                    continue
                if src[j] == q:
                    j += 1
                    break
                j += 1
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
    rows2 = []
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

    # RULE 2: an owning pointer acquired and NEVER FREED IN THE SAME FUNCTION.
    # Function-scoped, because that is the rule that would have caught #134's leak:
    # `check_fields_are_arrays()` acquired `hdr` and did not free it, while
    # `check_width_is_derived()` in the same file acquired and freed a variable of the
    # SAME NAME. A file-scoped version passes that, which is why the first version was
    # file-scoped and is not any more.
    acquires = 0
    # Every exempted acquisition, printed. A suppression that does not appear in the
    # output is a suppression nobody reads, and this audit has spent its whole life
    # arguing that a check nobody reads is not a check.
    deliberate = []
    for path in files:
        rel = os.path.relpath(path, ROOT)
        raw = open(path, "r", encoding="utf-8", errors="replace").read()
        clean = strip_comments(raw)
        bodies = top_level_bodies(clean)
        body_ranges = top_level_body_ranges(clean)
        raw_lines = raw.split("\n")
        for body_index, (lineno, body) in enumerate(bodies):
            for am in ACQUIRE.finditer(body):
                var = am.group(1)
                acquires += 1
                if re.search(
                        r"\bfree\s*\(\s*(?:&|\(\s*\w+\s*\*\s*\)\s*)?"
                        + re.escape(var) + r"\s*\)", body):
                    continue
                # A FUNCTION THAT RETURNS THE POINTER IS FORWARDING OWNERSHIP, not
                # leaking it, and this rule cannot judge the obligation because the
                # obligation is now in the caller. `tests/integration/
                # test_close_sites.c`'s `load()` is exactly that shape and it is
                # CORRECT -- three call sites free it, which macOS `leaks(1)` over
                # all 98 binaries confirms -- so flagging it would be the sixth false
                # positive this audit has produced and it would have earned the check
                # the deletion its first five nearly earned.
                #
                # #134's leak went through a wrapper of this shape too, and the
                # wrapper's CALLER is where the free was missing. So this exemption
                # is also the precise statement of what rule 2 cannot do: see the
                # output below, which says it in those words rather than implying it.
                if re.search(r"\breturn\s+(?:\(\s*\w+\s*\*\s*\)\s*)?"
                             + re.escape(var) + r"\s*;", body):
                    continue
                # THE DELIBERATE-LEAK EXEMPTION, and it is one file, one function and
                # one MARKER rather than a filename or a suppression switch.
                #
                # tests/integration/lsan_probe.c acquires a block and never frees it.
                # That is the entire purpose of the file: it is the test that proves
                # LeakSanitizer is live by leaking 64 KiB on purpose and failing unless
                # LSan reports it. Rule 2 cannot tell that from #134's leak -- it is
                # the same text shape -- and a check that cannot fail is worth less than
                # no check, so the exemption is here and is narrow.
                #
                # WHY IT IS A MARKER IN THE SOURCE rather than a path in this script: a
                # path here is invisible at the point somebody adds the next deliberate
                # leak, and a marker is not. The `audit-teardown:` prefix is chosen so
                # that `grep -rn 'audit-teardown:' tests/ src/` answers "where is this
                # rule bent, and why" without reading this file. The reason is REQUIRED
                # on the same line, so a bare marker does not parse: a suppression
                # someone cannot explain is a suppression nobody will review.
                #
                # THE LIMIT, STATED RATHER THAN DISCOVERED: this exemption covers rule 2
                # for ONE acquisition in ONE function of ONE file. Every other
                # acquisition in that file, and every line after it, is audited normally
                # -- so a genuine leak added to lsan_probe.c beside the deliberate one
                # is still red.
                # The marker is looked for in the RAW lines of this function, because
                # the cleaned body has every comment blanked out of it. See
                # top_level_body_ranges() for why that is a separate function rather
                # than an inline fix.
                raw_span = ""
                if body_index < len(body_ranges):
                    lo, hi = body_ranges[body_index]
                    raw_span = "\n".join(raw_lines[lo - 1:hi])
                # EVERY marker in the function is collected, not just the first, and
                # matched by name against THIS acquisition. Both halves matter: a
                # function with two acquisitions and one marker must exempt that one
                # and report the other, which is the limit the exemption's comment
                # claims and which a first-match search would not deliver.
                marked = {mm.group(1): mm.group(2).strip().rstrip(".")
                          for mm in DELIBERATE_LEAK.finditer(raw_span)}
                if var in marked:
                    deliberate.append((rel, lineno, var, marked[var]))
                    continue
                rows2.append((rel, lineno, var, am.group(0).strip()))

    print()
    if deliberate:
        print("    %d exempted: a DELIBERATE leak, declared in the source." %
              len(deliberate))
        for rel, lineno, var, why in deliberate:
            print("      %s:%d: %s -- %s" % (rel, lineno, var, why))
        print("    Each one carries an `audit-teardown: DELIBERATE LEAK <var> -- <why>`")
        print("    marker on the statement that drops the pointer, naming the owning")
        print("    variable and the reason. The exemption is for THAT acquisition only:")
        print("    a second acquisition in the same function, or in the same file, is")
        print("    audited normally and is red.")
        print()
    print("RULE 2 -- AN OWNING POINTER ACQUIRED AND NEVER FREED IN THE SAME "
          "FUNCTION. %d acquisition(s) in %d top-level function(s) across src/ and "
          "tests/." % (acquires, sum(len(top_level_bodies(strip_comments(
              open(p, "r", encoding="utf-8", errors="replace").read())))
              for p in files)))
    if rows2:
        print("    %d of them are never freed where they were acquired." % len(rows2))
    for rel, lineno, var, stmt in rows2:
        print("    %-46s %s" % (rel + ":" + str(lineno), stmt))
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
    print("RULE 2 IS FUNCTION-SCOPED, and it took two wrong versions to get there.")
    print("The first was file-scoped -- `hdr` is freed elsewhere in the same file, so")
    print("the file-scoped rule PASSED the leak it was written for. The second was")
    print("function-scoped on a signature-matching boundary, and it reported THREE")
    print("false positives on the shipped tree because the pattern did not match")
    print("every signature shape this tree writes. The third matches the boundary by")
    print("COLUMN -- a `{` at the start of a line is a function body, because every")
    print("nested brace in this tree is indented -- and has zero findings.")
    print("THE LIMIT, which is the cost of that choice, and it is EXACTLY the shape of")
    print("the leak rule 2 was written for. A pointer acquired in one function and")
    print("freed in ANOTHER is not seen: a function that RETURNS the acquire is")
    print("forwarding ownership and is exempted, because the obligation is now in a")
    print("function this rule cannot reason about. `test_close_sites.c`'s `load()` is")
    print("that shape and is correct today -- three call sites free it, and macOS")
    print("`leaks(1)` over all 98 binaries confirms it. #134's leak went through a")
    print("wrapper of the same shape, so RULE 2 WOULD NOT HAVE CAUGHT IT AS SHIPPED.")
    print("What caught it was Linux CI, and what stops it recurring is that the")
    print("test's wrapper now reads into a CALLER-PROVIDED BUFFER and owns nothing,")
    print("so there is no pointer left to lose. Rule 2 is the guard rail for the")
    print("DIRECT shape; the API change is the fix.")
    print()
    print("RULE 2 DOES NOT SEE THROUGH A WRAPPER, and that is not a caveat -- it is how")
    print("the leak it was written for got past every earlier version of this file.")
    print("#134's test read a source through `read_src()`, a one-line wrapper around")
    print("`tf_read_code()`, and the FUNCTION THAT CALLED THE WRAPPER forgot the free.")
    print("Rule 2 would not have caught that as shipped. The fix was therefore to")
    print("remove the possibility rather than to add the rule:")
    print("`tf_read_code_into(dst, cap, rel, ...)` reads into a CALLER-PROVIDED buffer")
    print("and the test's `read_src()` now owns nothing, so there is no pointer to")
    print("lose. Rule 2 is what keeps the other 19 direct sites paired.")
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
                             "no release call in the body (RULE 1):\n" % len(bad))
            for rel, lineno, name, _h, _s, _n in bad:
                sys.stderr.write("    %s:%d: %s\n" % (rel, lineno, name))
        if rows2:
            sys.stderr.write("audit-teardown --strict: FAIL: %d owning pointer(s) "
                             "acquired and never freed in the same function "
                             "(RULE 2):\n" % len(rows2))
            for rel, lineno, var, stmt in rows2:
                sys.stderr.write("    %s:%d: %s\n" % (rel, lineno, stmt))
        if bad or rows2:
            return 1
        print("audit-teardown --strict: OK (2 strict helpers both release; %d "
              "acquisition(s) paired, %d declared a deliberate leak)."
              % (acquires - len(deliberate), len(deliberate)))
    return 0


if __name__ == "__main__":
    sys.exit(main())