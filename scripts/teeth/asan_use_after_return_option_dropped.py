#!/usr/bin/env python3
"""teeth/asan_use_after_return_option_dropped.py -- drop the option the class needs.

THE FAULT
---------
`scripts/gate-linux-cell.sh` ran the suite under
`ASAN_OPTIONS=detect_leaks=1` and printed a count of `ERROR: AddressSanitizer` findings.
That count was about a class the image was not watching: measured in this project's own
debian bookworm container (gcc 12.2.0), with `detect_leaks=1` alone, a deliberate
stack-use-after-return is SILENT -- the read returns its value and the process exits 0
-- and it is reported only when `detect_stack_use_after_return=1` is added. That option's
DEFAULT is false in this image and true in gcc 16 on linux, so the cell's coverage was a
property of whichever gcc its image happened to ship.

The fix was one word in `ASAN_RUN_OPTS`, plus a probe that fails unless each class is
reported. This fault removes the word.

WHAT MUST HAPPEN, AND IT IS TWO ASSERTIONS
------------------------------------------
1. `tests/integration/asan_coverage_probe` goes RED, with
   `COVER stack-use-after-return NOT-COVERED`. This is the assertion that makes the
   coverage claim non-decorative: a probe that supplied the option ITSELF would be green
   in a cell that had dropped it, which is why the probe inherits the caller's
   ASAN_OPTIONS verbatim and appends only two reporting controls.
2. The CELL'S OWN REPORT changes -- `sh scripts/gate-linux-cell.sh --report-render` over
   the probe's real output must exit non-zero and print
   `SANITIZER COVERAGE INCOMPLETE`. Without this half, a green probe count and a green
   report mean nothing: the report is what a person reads.

WHY IT NEEDS A LINUX HOST AND A CONTAINER. The whole question is what THIS IMAGE's ASan
watches, and the answer differs by platform and by compiler -- measured across five
toolchains, and the class is off by default in three of them. The tooth therefore runs
in `scripts/teeth-linux.sh`, which refuses to start anywhere else, and the positive
control in that script establishes first that the shipped options are green, so a red
here can only be this fault.
"""

import os
import sys

TARGET = "scripts/gate-linux-cell.sh"
ORIGINAL = 'ASAN_RUN_OPTS="detect_leaks=1:detect_stack_use_after_return=1"'
FAULTED = 'ASAN_RUN_OPTS="detect_leaks=1"'


def main():
    path = os.path.join(os.getcwd(), TARGET)
    if not os.path.isfile(path):
        sys.stderr.write("teeth fault: %s not found\n" % TARGET)
        return 1
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    if ORIGINAL not in text:
        sys.stderr.write(
            "teeth fault: %s does not contain the expected ASAN_RUN_OPTS line, so "
            "this fault would be a no-op. If it has been reworded, this fault has to "
            "follow it -- which is the right outcome, because a fault script that "
            "quietly stopped applying is the worst kind of green.\n" % TARGET)
        return 1
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text.replace(ORIGINAL, FAULTED, 1))
    return 0


if __name__ == "__main__":
    sys.exit(main())