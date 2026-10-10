#!/usr/bin/env python3
"""teeth/asan_cell_coverage_statement_removed.py -- delete the ASan cell's coverage block.

THE FAULT
---------
`scripts/gate.sh`'s ASan+UBSan cell used to print a count of sanitizer findings and
nothing else. A count of zero is only a statement about what was being watched, and
the class `stack-use-after-return` -- the one that found this project's real
`nf_free()` registry defect -- defaults to OFF in Homebrew gcc 16 on macOS, so the
cell was reporting a clean bill of health for the exact failure mode that had already
bitten the tree.

The fix was: pass `detect_stack_use_after_return=1`, build the opt-in probes beside
the suite, run `asan_coverage_probe` directly with the cell's own ASAN_OPTIONS, and
print the same per-class statement the Linux cell prints.

This fault deletes that block -- the run of the probe, the render, and the check that
turns an unproved class into a red cell -- so the cell goes back to printing a count
beside nothing.

WHAT MUST BE RED, AND WHY IT IS NOT THE SAME FAULT AS ITS SIBLING
----------------------------------------------------------------
`report_coverage_statement_removed.py` deletes the statement from the SHARED RENDERER
in `scripts/gate-linux-cell.sh`, and it runs against `--report-selftest`. That proves
the renderer still says what it was watching.

This fault deletes the CELL'S USE of the renderer, which is a different edit: not a
line changed but a block removed, and removing a call is easier to do by accident than
to change a format string. Its instrument is `sh scripts/gate.sh --asan-selftest`,
which renders a canned complete and a canned incomplete ledger through the same
renderer the cell uses AND then asserts this gate's ASan cell still calls it. So:

  * renderer broken  -> caught by the sibling fault
  * cell no longer asks for the statement -> caught by THIS fault

One fault per failure mode. A single fault that removed both would prove only that
something was removed, and would leave the question "does either half still work
alone?" unmeasured.

IT ALSO COSTS NOTHING TO RUN: --asan-selftest needs no compiler, no docker, no Linux
and no build, so this is checked on the developer machine on every gate invocation --
which is the point, because macOS is exactly where this cell cannot be seen running.
"""

import os
import sys

TARGET = "scripts/gate.sh"

# The coverage block, exactly as it appears in the cell. Two assertions rather than
# one so a partial deletion is still caught, and so the script fails loudly rather
# than silently applying nothing.
PROBE_RUN = '''ASAN_OPTIONS="$asan_opts" "$ad/tests/integration/asan_coverage_probe" \\
            > "$ad.cov.log" 2>&1 || true
'''

RENDER_CALL = '''if bash "$root/scripts/gate-linux-cell.sh" --report-render < "$ad.cov.log" \\
                > "$ad.covreport.log" 2>&1; then
'''


def main():
    path = os.path.join(os.getcwd(), TARGET)
    if not os.path.isfile(path):
        sys.stderr.write("teeth fault: %s not found\n" % TARGET)
        return 1
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()

    if PROBE_RUN not in text:
        sys.stderr.write(
            "teeth fault: the probe invocation was not found in %s, so this fault would "
            "be a no-op. If the cell has been reworded this fault has to follow it.\n" % TARGET)
        return 1
    if RENDER_CALL not in text:
        sys.stderr.write(
            "teeth fault: the coverage render call was not found in %s, so this fault "
            "would be a no-op.\n" % TARGET)
        return 1

    text = text.replace(PROBE_RUN, "", 1)
    text = text.replace(RENDER_CALL, "if true; then\n", 1)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())