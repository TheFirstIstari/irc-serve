#!/usr/bin/env python3
"""check-portability.sh -- no non-POSIX library symbols in the tree.

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
preferable to no escape hatch, because its absence turns "we need this one" into "we
cannot have this one", and that is how a ratchet gets deleted.
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

    if not findings:
        print("ok: no non-POSIX library symbols in %d C/H files (%d symbols watched)"
              % (scanned, len(SYMBOLS)))
        return 0

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
    print("A line may opt out with a trailing `%s` if a symbol is genuinely wanted." % EXEMPT)
    return 1


if __name__ == "__main__":
    sys.exit(main())