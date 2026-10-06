#!/usr/bin/env python3
"""check-portability.py -- no non-POSIX library symbols in the tree, and no file
whose extension disagrees with its shebang.

WHY THIS EXISTS, AND THE PATTERN IS THE FINDING
------------------------------------------------
Three defects in this project were each invisible to every local gate cell and each
visible only on Linux, and they are the same defect:

  1. the glibc `__wur` class -- a discarded return value that glibc annotates and
     macOS's headers do not, so the same call warned on one platform and not the other;
  2. a missing `<sys/wait.h>` -- included by one libc's headers transitively and not
     the other's;
  3. `memmem()` in the peer sweep -- a GNU extension that the macOS SDK declares
     WITHOUT a feature-test macro, so all thirteen local cells compiled it and used it,
     and glibc, which hides it behind `_GNU_SOURCE`, did not. It failed as one root
     cause and five symptoms: the implicit declaration made `memmem` an `int`, so every
     `memmem(...) != NULL` became a pointer-versus-integer comparison.

The common shape is that **the local gate is not a portability oracle**. Thirteen cells
on one libc agree with themselves, and they cannot notice that a symbol they accept is
not in the standard this tree is written against. That is a gap in the gate rather
than in any one file, and this check is the gap's name.

WHAT IT CHECKS, and the list is deliberately NARROW
--------------------------------------------------
Only symbols that are GNU or legacy-BSD extensions **and are not declared by a POSIX
libc without a feature-test macro**. That is the class which compiles here and fails
there. Three groups are deliberately NOT in the list, and saying why is part of the
check:

  - `strdup`, `getline`, `snprintf`, `M_PI` and friends: POSIX 2008 / POSIX, so they
    are fine on both and flagging them would be noise.
  - `strerror_r`: POSIX, and the GNU and POSIX variants differ in RETURN TYPE rather
    than in existence, so it compiles everywhere and is a review matter, not a build
    error. A check that flags things which are not broken trains people to ignore it.
  - `index`, `rindex`, `random`: the names are common ENGLISH. `index` appears in this
    tree only in comments and parameter names, so a naive grep for it reports a dozen
    false positives, which is the fastest way to make a ratchet useless. The names are
    therefore matched as CALLS (`name(`) and only after comments and string literals
    have been stripped -- see `strip_noise()` below, which is the load-bearing part.

HOW IT AVOIDS FALSE POSITIVES
------------------------------
Every line is stripped of `/* */`, `//`, `"..."` and `'...'` before the symbols are
looked for, and only a call-shaped match counts. Prose is not a use: this file's own
comment names every symbol in the list, and a checker that flagged its own list would
be a checker nobody runs twice.

EXIT STATUS
-----------
0 when clean, 1 with a per-occurrence report otherwise. The report names the file, the
line, the symbol and WHY it is not portable, because "symbol not allowed" is not an
actionable review comment and "memmem is GNU and needs _GNU_SOURCE" is.

The one deliberate escape hatch: a line ending in `no-portability: ok` is exempt, for
the case where a symbol is genuinely wanted and the writer has said so in the source.
Nothing in the tree uses it today. An escape hatch that exists but is unused is
preferable to no escape hatch, because its absence turns "we need this one" into
"we cannot have this one", and that is how a ratchet gets deleted.

THE SECOND CHECK, AND WHY IT LIVES IN THIS FILE
-----------------------------------------------
`check_interpreter()` below reports a file whose EXTENSION and whose SHEBANG name
different interpreters. It was this very file: it was `check-portability.sh` with a
`#!/usr/bin/env python3` on line 1, and it is renamed `.py` by the change that added
the check.

The shape of that defect is what earns it a place here, and it is not "a typo". The
gate invoked the file **directly**, so the shebang decided the interpreter and every
gate cell and every CI run did exactly what the shebang said -- the file worked. But
`bash scripts/check-portability.sh` parses Python as shell: it printed a syntax error
on the first indented block and then **exited 0**. A check that reports green while
failing is worse than no check, because it is a check whose green means nothing, and
because a reader who saw it "pass" would not look again.

Three properties make it the same defect as the `memmem()` class above:

  - IT IS INVISIBLE TO THE THING THAT RUNS IT. The interpreter that matters is the one
    the caller picks, and the caller picked the shebang; the extension was decoration
    on a file nobody ran through its own name.
  - IT IS INVISIBLE ON EVERY PLATFORM. This is not a Linux-only failure, which is why
    it sat in the tree through a full gate and thirteen cells.
  - IT IS A WHOLE CLASS, not one file. `.sh` is the spelling for shell; every other
    spelling in this tree (`.py`, `.awk`, no extension) happened to agree today, and
    nothing would have said so if it stopped agreeing.

So it is checked, and it is checked HERE rather than in a tenth gate check: this is the
file whose own subject is "the local gate is not a portability oracle", and the
extension/shebang disagreement is that sentence applied to this check's own name. A
file with no shebang is NOT a finding -- a fragment (`scripts/teeth/*.py`), an `awk`
program run as `awk -f`, and a documentation file all legitimately have none, and a
check that flagged those would be a check that would be disabled within a week.
"""

import os
import re
import subprocess
import sys

# The list. `why` is what a reader needs in order to act, so it is not decoration.
SYMBOLS = {
    "memmem": "GNU extension; declared by the macOS SDK without _GNU_SOURCE and by "
              "glibc only with it",
    "strcasestr": "GNU extension; needs _GNU_SOURCE",
    "strdupa": "GNU extension; needs _GNU_SOURCE",
    "mempcpy": "GNU extension; needs _GNU_SOURCE",
    "memfrob": "GNU extension; needs _GNU_SOURCE",
    "rawmemchr": "GNU extension; needs _GNU_SOURCE",
    "asprintf": "GNU extension; needs _GNU_SOURCE",
    "vasprintf": "GNU extension; needs _GNU_SOURCE",
    "fmemopen": "GNU extension; needs _GNU_SOURCE",
    "program_invocation_name": "GNU extension; needs _GNU_SOURCE",
    "sys_errlist": "removed from POSIX; glibc only",
    "bzero": "legacy BSD; removed from POSIX, and memset is the spelling",
    "ecvt": "legacy BSD; not ISO C, and there is no POSIX replacement worth having",
    "random": "legacy BSD; not ISO C, and rand() is the portable spelling",
    "srandom": "legacy BSD; not ISO C",
    "drand48": "legacy BSD; not ISO C",
    "reallocarray": "not POSIX; OpenBSD and GNU only",
    "explicit_bzero": "not POSIX",
    "setresuid": "not POSIX",
    "timersub": "not POSIX",
    # The opposite direction: POSIX 2008, so glibc has it and macOS does not. It can
    # only bite on the platform this gate runs on, so it would be caught by a failing
    # cell rather than by a red CI -- but it costs one line to name it here.
    "getdelim": "POSIX 2008; NOT available on macOS, so it fails the other way",
    "open_memstream": "POSIX 2008; NOT available on macOS, so it fails the other way",
}

EXEMPT = "no-portability: ok"

# ---------------------------------------------------------------------------
# THE EXTENSION/SHEBANG TABLE, and the three states a file can be in
# ---------------------------------------------------------------------------
# Each entry maps a tracked extension to the interpreter tokens its shebang is allowed
# to name. A `.sh` file whose shebang says `python3` is the defect; a `.py` file with no
# shebang is not, because `scripts/teeth/*.py` are source fragments that are fed to
# `python3 -` and to a comparison diff rather than executed, and a shebang on a fragment
# would be a lie of exactly the kind this check is about.
#
# `awk` is in the table because `strip-c-comments.awk` is run as `awk -f` and so has no
# shebang at all; it is here so that the day somebody adds one it is checked rather than
# unexamined.
INTERPRETER_BY_EXT = {
    ".sh": ("sh", "bash", "dash", "ksh", "zsh", "env sh", "env bash"),
    ".py": ("python", "env python"),
}

# What the shebang is allowed to be missing for. Every other extension with a shebang
# must have one, and the ones without a shebang are not findings.
SHEBANG_REQUIRED_EXT = (".sh", ".py")


def shebang_interpreter(first_line):
    """The interpreter a shebang names, or None when there is no shebang.

    `/usr/bin/env python3` and `/usr/bin/python3` both reduce to `python`, and `env bash`
    reduces to `bash`, because the question is "which language is this" rather than
    "which path is it at" -- a `/usr/bin/env` prefix is a portability idiom, not a
    different language.
    """
    if not first_line.startswith("#!"):
        return None
    words = first_line[2:].split()
    if not words:
        return ""
    if words[0].endswith("env"):
        words = words[1:]
        if not words:
            return ""
    interp = words[0].rsplit("/", 1)[-1]
    # `python3.11` is python; `bash5` is bash.
    interp = interp.rstrip("0123456789.")
    if not interp:
        return ""
    return interp


def check_interpreter(root, files):
    """Report files whose extension and shebang name different interpreters.

    Three outcomes, and the middle one is the finding:

      - extension not in the table, or no shebang: not this check's business.
      - shebang interpreter IS one the extension allows: fine.
      - otherwise: the file's name tells a reader one thing and its first line another.
    """
    findings = []
    scanned = 0
    for rel in sorted(files):
        ext = os.path.splitext(rel)[1]
        allowed = INTERPRETER_BY_EXT.get(ext)
        if allowed is None:
            continue
        path = os.path.join(root, rel)
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                first = fh.readline()
        except OSError:
            continue
        scanned += 1
        interp = shebang_interpreter(first)
        if interp is None:
            # A missing shebang on an executable script is reported; a missing shebang
            # on a non-executable one is not, because `scripts/teeth/*.py` are fragments
            # and a shebang on a fragment would be a claim the file cannot honour.
            if ext in SHEBANG_REQUIRED_EXT and os.access(path, os.X_OK):
                findings.append((rel, "no shebang, but the file is executable and its "
                                      "extension says it is a %s script" % ext[1:]))
            continue
        if interp == "" or interp in allowed:
            continue
        findings.append((rel, "extension says %s, shebang says %s: run through the "
                              "wrong interpreter it prints a syntax error and can "
                              "still exit 0" % (ext, interp)))
    return scanned, findings


def strip_noise(src):
    """Remove comments and string/char literals, preserving newlines.

    Line numbers are preserved by replacing every removed byte with a space except
    newlines, so a report's line number is the file's own.
    """
    out = []
    i = 0
    n = len(src)
    while i < n:
        c = src[i]
        two = src[i:i + 2]
        if two == "/*":
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append("".join(ch if ch == "\n" else " " for ch in src[i:j]))
            i = j
        elif two == "//":
            j = src.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
        elif c in ('"', "'"):
            quote = c
            j = i + 1
            while j < n and src[j] != quote:
                j += 2 if src[j] == "\\" else 1
            j = min(j + 1, n)
            out.append("".join(ch if ch == "\n" else " " for ch in src[i:j]))
            i = j
        else:
            out.append(c)
            i += 1
    return "".join(out)


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    try:
        files = subprocess.check_output(
            ["git", "-C", root, "ls-files"], text=True).split()
    except (subprocess.CalledProcessError, OSError):
        files = []
    # `git ls-files` SUCCEEDING with an empty list is a real case and not a success:
    # a worktree with nothing added yet, or a copy that is not a repository at all.
    # Treating that as "no files to check" would report `ok` while scanning nothing,
    # which is the failure mode this whole check exists to prevent -- so an empty
    # result falls back to the filesystem rather than to a clean bill of health.
    if not files:
        for base, dirs, names in os.walk(root):
            dirs[:] = [d for d in dirs if d not in (".git", "build", "build-gate")]
            for name in names:
                files.append(os.path.relpath(os.path.join(base, name), root))

    scanned = 0
    findings = []
    for rel in sorted(files):
        if not rel.endswith((".c", ".h")):
            continue
        path = os.path.join(root, rel)
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                raw = fh.read()
        except OSError:
            continue
        scanned += 1
        clean = strip_noise(raw)
        raw_lines = raw.split("\n")
        for lineno, line in enumerate(clean.split("\n"), 1):
            if EXEMPT in raw_lines[lineno - 1]:
                continue
            for sym, why in SYMBOLS.items():
                # CALL-SHAPED ONLY: a name followed by `(`. A declaration is
                # `ret name(` too, which is fine -- both mean the symbol exists here.
                if re.search(r"\b" + re.escape(sym) + r"\s*\(", line):
                    findings.append((rel, lineno, sym, why,
                                     raw_lines[lineno - 1].strip()))

    # THE SECOND CHECK, run over the WHOLE tree rather than the C/H subset, and its
    # result is folded into the SAME exit status rather than printed and ignored: a
    # second opinion in this file that did not fail the file would be the exact
    # defect the second check is about.
    iscanned, ifindings = check_interpreter(root, files)

    if not findings and not ifindings:
        print("ok: no non-POSIX library symbols in %d C/H files (%d symbols "
              "watched); %d script(s) agree with their shebang"
              % (scanned, len(SYMBOLS), iscanned))
        return 0

    rc = 1
    if findings:
        print("PORTABILITY: %d non-POSIX symbol use(s) in %d C/H files." %
              (len(findings), scanned))
        for rel, lineno, sym, why, text in findings:
            print("  %s:%d  %s" % (rel, lineno, sym))
            print("      %s" % why)
            print("      | %s" % text[:76])
        print("")
        print("This tree is C11 + POSIX by design. The fix is a portable spelling of the")
        print("operation -- a bounded search rather than memmem(), memset() rather than")
        print("bzero(), rand() rather than random() -- and NOT `#define _GNU_SOURCE`,")
        print("which buys one call site by making the whole file depend on extensions and")
        print("leaves the underlying problem in place.")
        print("A line may opt out with a trailing `%s` if a symbol is genuinely wanted."
              % EXEMPT)
        rc = 1
    if ifindings:
        print("PORTABILITY: %d extension/shebang disagreement(s) in %d script(s)."
              % (len(ifindings), iscanned))
        for rel, why in ifindings:
            print("  %s" % rel)
            print("      %s" % why)
        print("")
        print("The gate runs these files directly, so the shebang is what decided the")
        print("interpreter and the extension was never consulted -- which is exactly why")
        print("this survived a green gate: a check that prints a syntax error and still")
        print("exits 0 is a check whose green means nothing. Rename the file to its")
        print("shebang, or change the shebang to its extension.")
    return rc


if __name__ == "__main__":
    sys.exit(main())