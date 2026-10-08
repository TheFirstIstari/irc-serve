#!/usr/bin/env python3
"""FAULT: packaging/debian/source/format names a format dpkg does not document.

WHAT THIS PROVES
----------------
That the source/format check is checking the VALUE LIST and not merely "this file is
not empty" or "this file has something that looks like a version".

THE CHOSEN VALUE IS DELIBERATE, and it is the whole point of the fault.
`3.0 (bogus)` SATISFIES dpkg's own parser regex --

    ^(\\d+)(?:\\.(\\d+))?(?:\\s+\\(([a-z0-9]+)\\))?$

-- because `bogus` matches `[a-z0-9]+`. So dpkg-source would accept it at the parse
step and go on to fail later, or produce a `.dsc` declaring a format it cannot build.
A check written as "does this match the pattern dpkg uses" would go GREEN on this
fault. A check written as "is this one of the two formats dpkg-source(1) documents for
a new package" goes red, which is the property worth having: the pattern is dpkg's,
and the value list is the DOCUMENTATION's, and only the second one stops a plausible
typo.

`1.0` is excluded from the accepted list on purpose even though it matches the regex,
because dpkg-source(1) calls the 1.0 fallback deprecated for new packages. Accepting
it would make the check agree with the absence-of-file bug it exists to catch.

NO sleep, NO PORT, NO TIMER: this rewrites one line of a text file.
"""

import os
import sys

FORMAT = os.path.join("packaging", "debian", "source", "format")

with open(FORMAT, "r", encoding="utf-8") as fh:
    before = fh.read()

if not before.strip().startswith("3.0"):
    sys.stderr.write("source_format_invalid: FAULT NOT APPLIED: %s does not contain a "
                     "3.0 format.\n" % FORMAT)
    sys.exit(1)

with open(FORMAT, "w", encoding="utf-8") as fh:
    fh.write("3.0 (bogus)\n")