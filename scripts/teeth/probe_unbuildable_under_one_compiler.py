#!/usr/bin/env python3
"""teeth/probe_unbuildable_under_one_compiler.py -- break ONE opt-in probe for ONE compiler.

THE FAULT
---------
`.github/workflows/ci_optin_probes` and `ci_macos` compile the two opt-in probes --
`tests/integration/lsan_probe.c` and `tests/integration/asan_coverage_probe.c` -- on
every push and every pull request, under gcc, upstream clang and Apple clang. Before
this pass no configuration in the project compiled either file, which is how
`lsan_probe.c` shipped a missing newline at EOF and a set-but-unused global, and how
`asan_coverage_probe.c` shipped a `[-Werror=dangling-pointer=]` failure under gcc 16
that no gate cell and no CI job could see.

THE FAULT IS THE EXACT SHAPE OF THAT LAST DEFECT, aimed at the compiler family that
found it. It adds one line to `asan_coverage_probe.c` that is a hard error under GCC
only:

    _this_identifier_does_not_exist_this_is_a_fault_injection();

Under GCC that is `error: '...' undeclared`, and the tree's `-Werror` is irrelevant --
it is a hard error on every compiler. The point is not that the file stops compiling
everywhere; the point is that a job which built the probes with only ONE compiler
would report green while the project's GCC line was red. That asymmetry is what the
three-compiler requirement buys, and this fault is the only way to know the
requirement is load-bearing rather than decorative.

WHAT MUST HAPPEN, AND IT IS TWO ASSERTIONS
------------------------------------------
1. The build of `asan_coverage_probe` under GCC fails. scripts/teeth.sh runs that
   exact configure-and-build as the instrument.
2. THE OTHER PROBE IS UNAFFECTED. `lsan_probe` is not touched, so it must still build.
   Without this second half the fault would only prove that a broken file breaks a
   build, which is true of every compiler and says nothing about the matrix.

WHY IT LIVES HERE AND NOT IN teeth-linux.sh. The question "does this file compile
under this compiler" is a COMPILE question, answerable on any machine that has the
compiler -- no container, no sanitizer runtime, no glibc. Running it in the Linux
teeth would mean paying a container build to learn something a four-second `cc -c`
already answers, and would leave the only instrument that checks the compile coverage
running on one platform, which is the mistake the probes themselves were.

WHY IT IS A SEPARATE FILE rather than a parameter on `asan_use_after_return_option_dropped.py`.
That fault is about a RUNTIME option and belongs where the answer exists, inside the
pinned image. This one is about COMPILATION, and mixing the two would make one file
claim to answer both while only running in one place.
"""

import os
import sys

TARGET = "tests/integration/asan_coverage_probe.c"

# Inserted immediately after the last #include, so it is in file scope and no
# function body can hide it. The exact text is asserted to be absent first: a fault
# that cannot find its anchor reports "applied" and the red that followed would prove
# nothing about the fix, which is the failure mode scripts/teeth.sh's staging step
# already had once.
ANCHOR = "#include <unistd.h>\n"

INJECTED = """
/* teeth fault injection: a hard error under GCC. See
 * scripts/teeth/probe_unbuildable_under_one_compiler.py. */
void _teeth_fault_this_identifier_does_not_exist(void);
void _teeth_fault_this_identifier_does_not_exist(void) { _teeth_fault_undeclared(); }
"""


def main():
    path = os.path.join(os.getcwd(), TARGET)
    if not os.path.isfile(path):
        sys.stderr.write("teeth fault: %s not found\n" % TARGET)
        return 1
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()

    if ANCHOR not in text:
        sys.stderr.write(
            "teeth fault: the anchor (%r) was not found in %s, so this fault would be a "
            "no-op. If the includes moved, this fault has to follow them -- which is the "
            "right outcome, because a fault script that quietly stopped applying is the "
            "worst kind of green.\n" % (ANCHOR.strip(), TARGET))
        return 1
    if "_teeth_fault_undeclared" in text:
        sys.stderr.write("teeth fault: the injection is already present in %s\n" % TARGET)
        return 1

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text.replace(ANCHOR, ANCHOR + INJECTED, 1))
    return 0


if __name__ == "__main__":
    sys.exit(main())