#!/usr/bin/env python3
"""FAULT: the Homebrew formula's `version` diverges from src/core/server.h.

WHAT THIS PROVES
----------------
That check-packaging.py's version cross-check reaches the THIRD packaging format.
The changelog and the PKGBUILD both had version checks before this pass; the formula
was the one that did not, and a Homebrew formula is where a wrong version is most
visible to a user, because `brew info irc-serve` prints it next to a binary that
reports something else.

WHY A FORMULA CANNOT DERIVE IT, restated because it is the thing a reader of this
fault will ask. `version` is evaluated by brew BEFORE anything is downloaded, so there
is no source tree to read `IRС_SERVE_VERSION` out of. The PKGBUILD gets away with a
`sed` because makepkg runs inside the unpacked source. A formula's only options are a
literal plus a check, or a literal plus nothing -- and this file makes the choice
literal-plus-check, which is a real check because this fault goes red.

This fault also leaves the formula's OWN `test do` block wrong, since that block
asserts the installed binary reports `irc-serve-#{version}`. That is deliberate: the
two are supposed to disagree together, and check-packaging.py is the instrument that
notices before `brew test` gets the chance.

NO sleep, NO PORT, NO TIMER: this rewrites one line of a text file.
"""

import os
import re
import sys

FORMULA = os.path.join("packaging", "homebrew", "irc-serve.rb")

with open(FORMULA, "r", encoding="utf-8") as fh:
    text = fh.read()

new, n = re.subn(r'^(\s*version\s+")0\.1\.0(")', r"\g<1>0.2.0\g<2>", text,
                 count=1, flags=re.M)
if n != 1:
    sys.stderr.write("formula_version_diverges: FAULT NOT APPLIED: no line reading "
                     "`version \"0.1.0\"` was found in %s.\n" % FORMULA)
    sys.exit(1)

with open(FORMULA, "w", encoding="utf-8") as fh:
    fh.write(new)