#!/usr/bin/env python3
"""FAULT: packaging/debian/changelog's version diverges from src/core/server.h.

WHAT THIS PROVES
----------------
scripts/check-packaging.py's claim that the Debian changelog and the header agree.
The check is the packaging side of a claim tests/integration/test_version_truth.c
also makes, and this fault exists because "the check exists" is not the same claim as
"the check fires".

WHAT A DIVERGENCE IS AND IS NOT
-------------------------------
It is NOT a hypothetical. A changelog is a record and it is updated by hand on every
version bump, which is precisely why it drifts: bump the header, forget the record.
The packaging consequence is a .deb whose metadata claims a version its binary does
not report, and nothing in the build says so -- `dpkg-buildpackage` checks that the
changelog PARSES, not that the number inside it is the number the source has.

The revision is kept (`-1`) on purpose. Only the upstream part is moved, so the
fault isolates version drift and cannot be caught by the source/format revision
cross-check that also runs in check-packaging.py: if the revision went away, this
fault would be caught by the wrong finding and would stop proving what it claims to.

NO sleep, NO PORT, NO TIMER: this rewrites one line of a text file.
"""

import os
import re
import sys

CHANGELOG = os.path.join("packaging", "debian", "changelog")

with open(CHANGELOG, "r", encoding="utf-8") as fh:
    text = fh.read()

new, n = re.subn(r"^irc-serve \(0\.1\.0(-1)\)", r"irc-serve (0.9.9\1)",
                 text, count=1, flags=re.M)
if n != 1:
    sys.stderr.write("changelog_version_diverges: FAULT NOT APPLIED: the first line "
                     "does not read `irc-serve (0.1.0-...)`. A fault nobody applied "
                     "proves nothing, and reporting that as a pass would be the one "
                     "outcome this file exists to prevent.\n")
    sys.exit(1)

with open(CHANGELOG, "w", encoding="utf-8") as fh:
    fh.write(new)