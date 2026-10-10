#!/usr/bin/env python3
"""teeth/report_coverage_statement_removed.py -- delete the coverage statement.

THE FAULT
---------
`scripts/gate-linux-cell.sh`'s report prints a count of sanitizer findings. It did
that for its whole life and said nothing about what was being watched, which is how a
cell went months reporting `AddressSanitizer 0` about a class its image did not enable.
The fix was to make the report STATE ITS COVERAGE: one `COVER <class> PROVED` line per
AddressSanitizer error class, a loud banner when one is unproved, and a machine-readable
`report-complete:` trailer.

This fault deletes the coverage block from `emit_cell_report()` and the completeness
marker from `finish_report()` -- that is, it turns the report back into exactly what it
was: a count of findings and nothing else.

WHAT IT MUST BE CAUGHT BY, AND WHY IT IS WORTH A FAULT
------------------------------------------------------
`--report-selftest`, which needs no docker, no Linux and no build, and which
`scripts/gate.sh` therefore runs on every machine on every invocation. Without this
fault the self-test is a plausible-looking assertion nobody has ever seen fail; with
it, the question "would I notice if someone deleted the coverage statement?" has a
measured answer, and the answer is yes.

The three teeth for this cell's honesty are split across two machines on purpose, and
the split is not an accident of convenience:

  * THIS ONE -- the report's SHAPE -- runs anywhere, because it is a property of a
    shell function. Running it only on the Linux box would mean it is re-verified
    once a release instead of once a commit.
  * `scripts/teeth-linux.sh` -- that the classes really ARE watched in the container --
    runs only on Linux, because that is the only place the answer exists. A test for
    "is ASan watching stack-use-after-return in the debian bookworm image" that ran on
    macOS would be a test of macOS's ASan wearing the image's name.
"""

import os
import sys

TARGET = "scripts/gate-linux-cell.sh"

# The two blocks. Each is an exact string, and the script FAILS if either is absent
# rather than skipping: a fault that could not find its target would otherwise report
# "applied" and the red that followed would prove nothing about the fix.
COVERAGE_BLOCK = """    printf '    sanitizer coverage -- what was being watched, proved per class:\\n'
    printf '%s\\n' "$ledger" | sed '/^$/d;s/^/      /'
"""

TRAILER_BLOCK = """    printf '    report-complete: build=%s coverage=%s tree=%s dirty=%s\\n' "$bt" \\
        "$([ "$complete" = "1" ] && echo complete || echo INCOMPLETE)" \\
        "$tree" "$dirty"
"""


def main():
    path = os.path.join(os.getcwd(), TARGET)
    if not os.path.isfile(path):
        sys.stderr.write("teeth fault: %s not found\n" % TARGET)
        return 1
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()

    if COVERAGE_BLOCK not in text:
        sys.stderr.write("teeth fault: the coverage block was not found in %s, so "
                         "this fault would be a no-op\n" % TARGET)
        return 1
    if TRAILER_BLOCK not in text:
        sys.stderr.write("teeth fault: the completeness trailer was not found in %s, "
                         "so this fault would be a no-op\n" % TARGET)
        return 1

    text = text.replace(COVERAGE_BLOCK, "", 1)
    text = text.replace(TRAILER_BLOCK, "", 1)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())