#!/usr/bin/env python3
"""teeth/linux_cell_dirty_flag_suppressed.py -- make the cell's result unattributable again.

THE FAULT
---------
`scripts/gate-linux-cell.sh` copies the tree into a scratch directory with `rsync` --
the WORKING TREE, committed or not. The comment directly above that line used to say
`git archive` and went on to claim the cell "cannot be affected by an uncommitted local
change" and "answers 'does the commit build on Linux'". Neither was true, and the
difference is not cosmetic: the last pass lost a whole fault-injection run to exactly
that confusion, where a STAGED COPY's script built the clean tree sitting beside it
and reported PASS for a fault that was never in the build.

The fix has two halves. The comment now describes `rsync`. And every report the cell
prints -- the banner, each per-configuration report, and the machine-readable
`report-complete:` trailer -- carries the commit AND a dirty flag, because a result
that is about uncommitted code has to say so on the same screen a reader is looking
at. The cell additionally REFUSES to report anything at all for a tree it cannot name.

This fault suppresses the dirty flag: `tree_descriptor` stops asking git whether the
tree is dirty, so every report says `clean` about a working tree with edits in it.

WHAT MUST BE RED, AND WHY IT IS WORTH A FAULT
---------------------------------------------
`--report-selftest`, which needs no docker, no Linux and no build, and which
`scripts/gate.sh` therefore runs on every gate invocation on the developer's machine.

Without this fault the dirty flag is a plausible-looking string in a report nobody has
ever seen absent. With it, the question "would a result about uncommitted code be
visibly different from one about a commit?" has a measured answer, and the answer is
yes -- which is the whole difference between a gate that can be trusted about its own
subject and one that cannot.
"""

import os
import sys

TARGET = "scripts/gate-linux-cell.sh"

# The three-part detector: commit, dirty decision, default. Replacing the decision
# makes every report claim `clean`; the default stays so the rest of the function
# still returns something well formed and the failure is attributable to the flag
# rather than to a crash.
ORIGINAL = '''    if [ -n "$(git -C "$dir" status --porcelain 2>/dev/null)" ]; then
        printf '%s DIRTY\\n' "$sha"
    else
        printf '%s clean\\n' "$sha"
    fi'''

FAULTED = '''    printf '%s clean\\n' "$sha"'''

# The trailer line is asserted to be gone too, so the fault is not merely "the flag is
# always zero": it removes the marker from the machine-readable line as well, which is
# the second of the two independent ways the flag could go missing.
TRAILER = '''    printf '    report-complete: build=%s coverage=%s tree=%s dirty=%s\\n' "$bt" \\'''
TRAILER_FAULTED = '''    printf '    report-complete: build=%s coverage=%s tree=%s\\n' "$bt" \\'''


def main():
    path = os.path.join(os.getcwd(), TARGET)
    if not os.path.isfile(path):
        sys.stderr.write("teeth fault: %s not found\n" % TARGET)
        return 1
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()

    if ORIGINAL not in text:
        sys.stderr.write(
            "teeth fault: the dirty decision in tree_descriptor() was not found in %s, "
            "so this fault would be a no-op. If the function has been reworded this "
            "fault has to follow it.\n" % TARGET)
        return 1
    if TRAILER not in text:
        sys.stderr.write(
            "teeth fault: the report-complete trailer carrying the dirty flag was not "
            "found in %s, so this fault would only half apply.\n" % TARGET)
        return 1

    text = text.replace(ORIGINAL, FAULTED, 1)
    text = text.replace(TRAILER, TRAILER_FAULTED, 1)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())