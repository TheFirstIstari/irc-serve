#!/usr/bin/env python3
"""teeth/ci_sanitizers_coverage_statement_removed.py -- delete ci_sanitizers' coverage block.

THE FAULT
---------
The `ci_sanitizers` job on ubuntu-22.04 prints a count of LeakSanitizer findings and a
count of AddressSanitizer findings. It did that for its whole life and said nothing
about what was being watched. `stack-use-after-return` defaults to OFF in the gcc on
that image, so the count was about three of the four classes the project names -- and
that class is the one that found this project's real `nf_free()` registry defect.

The fix was `ASAN_OPTIONS: detect_leaks=1:detect_stack_use_after_return=1`, plus a
step that runs `asan_coverage_probe` with the job's own options and renders the same
per-class statement the Linux cell renders, through `gate-linux-cell.sh
--report-render`, failing the job when a class is unproved.

This fault deletes that step.

WHAT MUST BE RED, AND WHY A WORKFLOW FILE NEEDS A SEPARATE FAULT
----------------------------------------------------------------
Three cells in this repository print sanitizer counts: the Linux cell, this gate's own
ASan cell, and this CI job. All three now call ONE renderer, so a change to the
renderer is caught once. But a renderer nobody calls is a renderer that can be edited
to say anything at all without anything noticing, and "nobody calls it" is reached by
DELETING A STEP -- not by editing a format string, and not by anything the existing
faults look for.

So `sh scripts/gate.sh --asan-selftest` asserts the call site is present in
`.github/workflows/ci.yml`, and this fault removes it. The sibling
`asan_cell_coverage_statement_removed.py` does the same for this gate's own cell, and
the two are separate on purpose: two call sites, two ways to lose one, two faults.

WHAT THE INSTRUMENT IS AND IS NOT. It is a SOURCE check over the workflow file, and it
is labelled as one in the message it prints. It cannot know whether the step that was
deleted would have worked; it knows it is gone. That is the whole of what a step that
does not exist can be checked for, and claiming more would be the same overstatement
this project keeps removing from its own reports.
"""

import os
import sys

TARGET = ".github/workflows/ci.yml"

# The step's identifying line: the call into the shared renderer. This is the LAST
# such call in the workflow and it sits inside ci_sanitizers, which is why the
# workflow as a whole is a safe place to look for it: there is exactly one.
RENDER_CALL = "bash scripts/gate-linux-cell.sh --report-render <build/asan-coverage.log"

STEP_NAME = "State what the sanitizers were watching"


def main():
    path = os.path.join(os.getcwd(), TARGET)
    if not os.path.isfile(path):
        sys.stderr.write("teeth fault: %s not found\n" % TARGET)
        return 1
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()

    if RENDER_CALL not in text:
        sys.stderr.write(
            "teeth fault: %s does not contain the coverage render call, so this fault "
            "would be a no-op. If the step has been reworded this fault has to follow "
            "it.\n" % TARGET)
        return 1
    if STEP_NAME not in text:
        sys.stderr.write("teeth fault: the coverage step's name was not found in %s\n" % TARGET)
        return 1

    # Both halves of the step, and not just the call: deleting the call alone would
    # leave a step named "State what the sanitizers were watching" that states
    # nothing, which is a worse report than no step at all.
    text = text.replace(RENDER_CALL, "true  # teeth: coverage render removed", 1)
    text = text.replace(STEP_NAME, "Coverage (removed)", 1)

    # And the option the step's own ASAN_OPTIONS duplicates. The suite still needs it;
    # what goes is the copy that exists so the PROBE runs under the same options the
    # suite did, which is the whole reason that second env block is there.
    dup = """        env:
          ASAN_OPTIONS: detect_leaks=1:detect_stack_use_after_return=1
        run: |
          set -euo pipefail
          probe=build/tests/integration/asan_coverage_probe"""
    if dup in text:
        text = text.replace(dup, """        run: |
          set -euo pipefail
          probe=build/tests/integration/asan_coverage_probe""", 1)

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())