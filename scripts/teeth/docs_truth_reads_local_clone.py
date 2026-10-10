#!/usr/bin/env python3
"""teeth/docs_truth_reads_local_clone.py -- point the docs-truth check at THIS clone.

THE FAULT
---------
One word. `scripts/check-docs-truth.py` read the repository's tags out of
`refs/tags`, which is the local clone, so a clone carrying tags `origin` does not have
got a different answer than CI -- and the answer was a function of whose machine ran
it. The fix routes every repository-state claim through
`scripts/gen-rollback-table.py`, which asks `git ls-remote --tags origin` and reads the
metadata from a private namespace fetched from that remote.

This fault rewrites the default remote from `origin` to `.` -- the local repository.
It is the original defect, in its original words, applied by a script rather than
argued about.

WHY THE WORD IS `DEFAULT_REMOTE` AND NOT A FLAG
-----------------------------------------------
Because the default IS the thing that was wrong. A check whose correctness depends on
how it is invoked is a check whose correctness a reader cannot see, and a fault hook
for it would make the production code carry the shape of the bug in order to be
testable against it. (The check does read `DOCS_TRUTH_REMOTE` from the environment --
that is a named input, and it is what this fault's own teeth run uses. It defaults to
`origin` and the fault moves the DEFAULT.)

WHAT MUST HAPPEN
----------------
`scripts/check-docs-truth.py` goes RED, and it goes red for the RIGHT reason: it must
name a tag the remote `.` has and the committed table does not. A red that said only
"the repository could not be read" would be a different failure, and a check that
cannot ask the question is not the same instrument as one that asks it wrongly.

The machine this runs on has tags `origin` does not -- measured at the time of
writing: the clone held 11 and `origin` held 9 -- so the fault has something real to
find rather than a contrived difference.
"""

import os
import sys

TARGET = "scripts/check-docs-truth.py"
ORIGINAL = 'DEFAULT_DOCS_REMOTE = "origin"'
FAULTED = 'DEFAULT_DOCS_REMOTE = "."'


def main():
    path = os.path.join(os.getcwd(), TARGET)
    if not os.path.isfile(path):
        sys.stderr.write("teeth fault: %s not found\n" % TARGET)
        return 1
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    if ORIGINAL not in text:
        sys.stderr.write("teeth fault: %s does not contain the expected default "
                         "remote, so this fault would be a no-op\n" % TARGET)
        return 1
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text.replace(ORIGINAL, FAULTED, 1))
    return 0


if __name__ == "__main__":
    sys.exit(main())