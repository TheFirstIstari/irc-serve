#!/usr/bin/env python3
"""FAULT: packaging/arch/PKGBUILD's pkgver is a LITERAL instead of a derivation.

WHAT THIS PROVES
----------------
That check-packaging.py's "pkgver is derived, not typed" check has teeth, and that it
fails for the right reason rather than by accident.

WHY THIS FAULT IS THE INTERESTING ONE
-------------------------------------
Two different instruments watch this line, and it is worth being precise about which
is which:

  * tests/integration/test_version_truth.c asserts the PKGBUILD contains no literal
    `pkgver=`, and separately EXECUTES the sed derivation in a child process and
    compares its output with the header. That is a C test and it needs a built binary.
  * scripts/check-packaging.py asserts the same two things from the packaging side, in
    Python, in under a second, with no build. That is what makes the claim cheap
    enough to run on every gate invocation.

This fault therefore trips BOTH. scripts/teeth.sh drives the Python one, because that
is the instrument whose independence from a build is the thing worth proving here; the
C test catching it too is recorded in the harness's summary rather than left for a
reader to assume.

THE FAULT IS WRITTEN THE WAY THE BUG WAS ACTUALLY WRITTEN. Replacing the derivation
with `pkgver=0.1.0` is not a hypothetical mutation: it is what a maintainer under
time pressure does, and it is the reason `IRC_SERVE_VERSION` exists in the header at
all. The correct number is used, so the ONLY thing wrong with the file is that it is
now a second copy of the version rather than a reading of the first.

NO sleep, NO PORT, NO TIMER: this rewrites one line of a text file.
"""

import os
import re
import sys

PKGBUILD = os.path.join("packaging", "arch", "PKGBUILD")

with open(PKGBUILD, "r", encoding="utf-8") as fh:
    text = fh.read()

# The derivation is one line, and it is matched on its shape rather than on a line
# number so that editing the comments above it cannot silently turn this fault into a
# no-op that still reports success.
new, n = re.subn(r"^pkgver=\$\(sed -n .*$", "pkgver=0.1.0", text, count=1, flags=re.M)
if n != 1:
    sys.stderr.write("pkgbuild_pkgver_hardcoded: FAULT NOT APPLIED: no line matching "
                     "`pkgver=$(sed -n ...` was found in %s.\n" % PKGBUILD)
    sys.exit(1)

with open(PKGBUILD, "w", encoding="utf-8") as fh:
    fh.write(new)