#!/usr/bin/env bash
# gate-linux-cell.sh -- the Linux cell: glibc, ASan + LeakSanitizer + UBSan, in docker.
#
# WHY THIS FILE IS THE SIXTH ANSWER TO THE SAME QUESTION
# ------------------------------------------------------
# This project has been bitten five times by the same shape, and the shape is not "a
# bug": it is "the local gate is not an oracle". glibc's `__wur`, a missing
# <sys/wait.h>, memmem(), a `tf_done()` leak and a 64 KiB test leak were each invisible
# to thirteen macOS cells and visible only on Linux. Then, on a real Linux machine:
#
#   * `debian/rules` shipped for a year with no `--buildsystem=cmake`, so debhelper
#     autodetected the top-level Makefile, dh_auto_configure printed the make help text,
#     exited 0, and NOTHING WAS BUILT.
#   * `nf_free()` did not unregister a node from tf_register's registry, so
#     `tf_done()` called nf_kill() on a pointer into a RETURNED stack frame --
#     ASan stack-use-after-return. ASan's runtime option for that is ON by default with
#     gcc on Linux and OFF by default with Apple clang, so the same source reads as a
#     harmless stale pointer on one platform and a fatal error on the other.
#
# Every one of those is invisible to a gate that only ever runs on Darwin. This cell is
# the gate answering the question properly: it runs the suite on glibc under all three
# sanitizers, in a container, on demand.
#
# HOW IT RUNS, AND WHY IT IS A SEPARATE SCRIPT
# --------------------------------------------
# scripts/gate.sh runs on macOS and has to keep running there. Everything this cell
# needs -- docker, a Linux kernel, a container image, a writable bind mount -- is
# unavailable or meaningless there. So this is a separate script that gate.sh CALLS,
# rather than a block inside gate.sh: a self-contained program that can be run by hand,
# by CI, or by a person bisecting a Linux-only failure, with one command and no
# arguments.
#
#   scripts/gate-linux-cell.sh [--keep] [--no-probe]
#
# IT DEGRADES, AND THE DEGRADATION IS VISIBLE. Three outcomes, three exit codes:
#
#   0  RAN AND PASSED.
#   1  RAN AND FAILED. A real Linux-only defect, or a real build failure.
#   3  DID NOT RUN. No docker, no daemon, no image, wrong kernel, or the tree is not
#      on a Linux host.
#
# Exit 3 exists so that "this cell did not run" is a THIRD thing and cannot be confused
# with the second. A gate cell that cannot distinguish "passed" from "was skipped" is
# the decorative-check failure this project keeps finding -- a check that prints OK for
# work it did not do -- and the whole reason this script is a separate program with its
# own exit code is so that gate.sh can print a word for it.
#
# WHAT IT BUILDS, and why these flags and not others:
#   -DIRC_SANITIZE=ON              the project's own opt-in ASan+UBSan build
#   -DIRC_LSAN_PROBE=ON            builds the two opt-in sanitizer probes:
#                                  tests/integration/lsan_probe.c, which leaks 64 KiB
#                                  and fails unless LSan names it, and
#                                  tests/integration/asan_coverage_probe.c, which
#                                  provokes one finding per ASan error class and fails
#                                  unless ASan names each one
#   -DCMAKE_BUILD_TYPE=Release     the configuration the .deb ships and the one CI runs
#   -DWITH_TLS=OFF and =ON         BOTH, because glibc's TLS stack is a different
#                                  library from its libc and one of the five historical
#                                  defects was in it
#   -DBUILD_TESTING=ON             without it there is nothing to run
#
# WHAT IT RUNS WITH, and why each option is written out rather than inherited:
#
#   detect_leaks=1                  LeakSanitizer is a runtime switch, so it belongs
#                                   to the RUN and not to the build. An ASan binary
#                                   that is merely linked against libasan reports
#                                   memory errors and reports nothing about leaks, and
#                                   a gate that confuses the two is the suppressed-check
#                                   failure in its most respectable disguise.
#
#   detect_stack_use_after_return=1 ADDED IN THIS PASS, and it is the whole reason the
#                                   cell's report now states its coverage. MEASURED on
#                                   the container this script runs in, over a
#                                   deliberate use-after-return: with
#                                   detect_leaks=1 alone the class is SILENT -- the
#                                   read returns 7 and the process exits 0. With this
#                                   option set it is reported and the process exits
#                                   non-zero. The default is FALSE in debian bookworm's
#                                   gcc 12.2.0 (measured with ASAN_OPTIONS=help=1)
#                                   and TRUE in gcc 16.2.1 and clang 22.1.8 on
#                                   linux, and FALSE in both gcc 16.2.0 and Apple
#                                   clang 21.0.0 on macOS. It is therefore a
#                                   property of the toolchain, not of the code, and a
#                                   cell that inherits it is reporting whichever
#                                   default its image happened to ship. That is the
#                                   class which found this project's real nf_free()
#                                   defect, so it is written down here rather than
#                                   hoped for.
#
# THE TOOLCHAIN DECISION, stated because the obvious alternatives were measured
# rather than argued about:
#
#   * THE CONTAINER IS KEPT, and its base image is NOT upgraded. The measurement
#     above is the argument: gcc 12.2.0 HONOURS detect_stack_use_after_return=1 and
#     reports the class correctly when it is set, so the container loses no coverage
#     by being gcc 12 -- the only thing it was missing was the option, and the option
#     is one word. Upgrading the base image would have changed the default from false
#     to true as a side effect of a gcc release rather than by a decision here, and
#     would have spent the pinned base image that this project's .deb target also
#     builds against (scripts/build-debian-package.sh uses debian:bookworm too). A
#     coverage claim that depends on an image rebuild is not a claim this cell can
#     assert; this one can.
#   * A NATIVE RUN IS NOT ADDED. The "newer gcc catches what the container misses"
#     argument is measured and it is TRUE of the DEFAULT (gcc 16.2.1 on linux has the
#     class on by default) but it is not a reason for a second cell, because this
#     project ALREADY has that coverage twice: ci_linux_cachyos runs the suite on
#     linux with gcc 16.2.1 natively, and gate.sh's own ASan+UBSan cell runs the
#     memory-error half on macOS. What was missing was not a compiler; it was any
#     assertion that a class was live in a cell that reported a count for it. That is
#     what the probe is, and it is cheaper than a build.
#   * WHAT IS GIVEN UP, and it is real: gcc 12's libasan and gcc 16's are DIFFERENT
#     IMPLEMENTATIONS, so with identical options these two cells are not the same
#     oracle. Findings they disagree about remain possible and are not resolvable
#     from inside this script.
#
# COST, WHICH IS REAL AND IS NOT HIDDEN: two full builds of the whole suite plus two
# probe executables, in a container, on a machine with 32 cores this is about two
# minutes. It is opt-in at the gate level (--linux) precisely because of that: it is
# the most expensive cell in the gate by a wide margin and it is the only one that can
# see a leak.

set -uo pipefail   # NOT -e: every failure below is reported, not aborted on.

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
root=$(cd -- "$here/.." && pwd)

KEEP=0
PROBE=1
SELFTEST=0
RENDER=0
while [ $# -gt 0 ]; do
    case "$1" in
        --keep)     KEEP=1 ;;
        --no-probe) PROBE=0 ;;
        # --report-selftest renders the report from canned inputs and asserts that the
        # rendered text still carries what the report is FOR. It exists because the
        # other two teeth for this file's honesty need a container, and a check whose
        # evidence costs two minutes of container build is a check that gets run once.
        # It needs no docker, no Linux and no build, so gate.sh runs it on every
        # machine on every run.
        --report-selftest) SELFTEST=1 ;;
        # --report-render reads COVER lines on stdin and prints the report the cell
        # would print for them. It exists for scripts/teeth-linux.sh, which has to
        # show that an unproved class CHANGES THE CELL'S REPORT, and re-implementing
        # the renderer there to do it would prove the teeth script's copy of the
        # report rather than the cell's.
        --report-render)  RENDER=1 ;;
        # The header, up to the `set -uo pipefail` line that ends it. A LINE COUNT was
        # here, and it was wrong the first time this file's header grew, which is the
        # cheapest possible demonstration of why a count is worse than a delimiter.
        # `grep -v` rather than a sed script with a block: the block form is a GNU
        # extension and this file has to print its own help on a BSD sed.
        -h|--help)  sed -n '2,/^set -uo pipefail/p' "$0" \
                       | grep -v '^set -uo pipefail'; exit 0 ;;
        *) echo "gate-linux-cell.sh: unknown argument '$1'" >&2; exit 2 ;;
    esac
    shift
done

# ---------------------------------------------------------------------------
# THE REPORT, AND WHY IT IS A FUNCTION.
# ---------------------------------------------------------------------------
# This cell printed a count of sanitizer findings and nothing else, and a count of
# zero is a statement about what was being watched. When a class is not being
# watched -- and one was not, for as long as this file existed -- the same count of
# zero comes out, and a reader has no way to tell a clean run from a blind one. The
# report now says which classes were proved live, and says so in a form a script can
# check, because a coverage statement that only a human reads is a coverage statement
# nobody reads twice.
#
# COVERAGE_CLASSES is the list of AddressSanitizer error classes this cell claims to
# cover. It is the SAME list tests/integration/asan_coverage_probe.c proves, and the
# two are checked against each other by --report-selftest: a class added to one and
# not the other would be a class the report names and nothing watches, which is the
# failure this whole change is about, so it is the one thing the self-test refuses.
COVERAGE_CLASSES="heap-use-after-free stack-use-after-scope heap-buffer-overflow stack-use-after-return"

# These two are defined HERE rather than next to the header echo, because the
# report-only modes above need BUILD_TYPE and a reader comparing the two blocks should
# find one definition of each rather than two.
#
# BUILD_TYPE is reported, not just configured, and the reason is in the file header: a
# Release sanitizer number is a claim about -O3, and -O3 can delete an allocation.
# ASAN_RUN_OPTS is written out in full rather than inherited, because every option in
# it is a DEFAULT THAT DIFFERS BETWEEN TOOLCHAINS -- measured across five, and the one
# that differs in this image is detect_stack_use_after_return.
BUILD_TYPE=Release
ASAN_RUN_OPTS="detect_leaks=1:detect_stack_use_after_return=1"

# coverage_complete <ledger> -- returns 0 when EVERY class in COVERAGE_CLASSES appears
# in the ledger as PROVED, and 1 otherwise.
#
# SINGLE-SOURCED, and deliberately not "is there no NOT-COVERED line in the ledger".
# A class that is ABSENT from the ledger must count as uncovered, because the defect
# this whole change is about is precisely a class that was quietly missing: a ledger
# with three classes and no fourth line would pass the absence-of-NOT-COVERED test and
# report complete. Asking "is each named class present and proved" cannot be satisfied
# by saying less.
coverage_complete() {
    local ledger="$1" c

    [ -n "$ledger" ] || return 1
    for c in $COVERAGE_CLASSES; do
        printf '%s\n' "$ledger" | grep -q "^COVER $c PROVED\$" || return 1
    done
    return 0
}

# emit_cell_report <build-type> <ctest-totals> <findings-line> <coverage-ledger>
#
# The ledger is the probe's own COVER lines, already formatted, so the report does not
# re-derive a verdict the probe produced. THE ORDER OF THE ARGUMENTS IS THE ORDER OF
# THE LINES, deliberately: this is a report a person reads top to bottom, and the two
# numbers it contains are only meaningful next to each other, so nothing between them
# moves.
emit_cell_report() {
    local bt="$1" totals="$2" findings="$3" ledger="$4"

    printf '    %s\n' "$totals"
    printf '    sanitizer findings: %s\n' "$findings"
    # THE BUILD TYPE IS IN THE REPORT, not only in the configure line, and the line
    # under it says why. MEASURED, and it is in tests/integration/lsan_probe.c: at
    # -O3 -DNDEBUG a child that allocates 64 KiB, writes it and never reads it has
    # the ALLOCATION ELIMINATED, so LeakSanitizer has nothing to report and a green
    # "0 leaks" is a statement about a compiler's optimiser rather than about this
    # tree. Every sanitizer number this cell reports is therefore a claim about ONE
    # build configuration, and a reader who does not know which was looking at a
    # claim they could not make.
    printf '    build type         : %s\n' "$bt"
    printf '    (a "0 findings" line is a claim about THIS build only: at -O3 the\n'
    printf '     compiler can delete an allocation, so a leak a Debug build reports\n'
    printf '     is not reported by a Release one. See tests/integration/lsan_probe.c)\n'
    printf '    sanitizer coverage -- what was being watched, proved per class:\n'
    printf '%s\n' "$ledger" | sed '/^$/d;s/^/      /'
}

# finish_report <build-type> <coverage-complete:0|1>
#
# The banner and the trailer. The trailer is machine-readable ON PURPOSE and is what
# --report-selftest asserts on: a report whose coverage statement has been edited out
# has to be visibly incomplete to something other than a reader's memory, or removing
# it is a change nobody would notice.
finish_report() {
    local bt="$1" complete="$2"

    if [ "$complete" = "1" ]; then
        printf '    COVERAGE STATEMENT: %s classes, all proved live this run.\n' \
            "$(printf '%s\n' $COVERAGE_CLASSES | wc -l | tr -d ' ')"
    else
        printf '\n'
        printf '    !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n'
        printf '    !!  SANITIZER COVERAGE INCOMPLETE -- THE COUNTS ABOVE DO NOT\n'
        printf '    !!  MEAN WHAT THEY LOOK LIKE\n'
        printf '    !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n'
        printf '    The counts above are real, and they are counts of findings in a\n'
        printf '    class of error this run was NOT watching. A "0 findings" line\n'
        printf '    below an incomplete coverage statement means nothing at all.\n'
        printf '    See the NOT-COVERED lines above for the class and the option.\n'
        printf '\n'
    fi
    printf '    report-complete: build=%s coverage=%s\n' "$bt" \
        "$([ "$complete" = "1" ] && echo complete || echo INCOMPLETE)"
}

# render_report <build-type> <ledger> <totals> <findings> -- the whole report, and the
# single place that decides whether it is complete. One function so that the cell's own
# run, the self-test and --report-render cannot drift apart: three copies of "is this
# report complete" is three answers, and this file's defect was one answer too few.
#
# Exit status is the completeness verdict, so a caller that pipes this into `&&` gets
# the gate behaviour for free. The `local` on the argument matters because
# coverage_complete reads its argument from a pipeline in a subshell.
render_report() {
    local bt="$1" ledger="$2" totals="$3" findings="$4"

    emit_cell_report "$bt" "$totals" "$findings" "$ledger"
    if coverage_complete "$ledger"; then
        finish_report "$bt" 1
    else
        finish_report "$bt" 0
        return 1
    fi
}

# probe_declared_classes: the class list AS THE PROBE DECLARES IT, read out of its
# source rather than out of this file.
#
# WHY THIS EXISTS, and it closes a hole the first version of the self-test had. The
# self-test iterates $COVERAGE_CLASSES to check that each one is named in the report,
# so DELETING a class from that list deletes the check on it: a report that quietly
# stopped claiming heap-buffer-overflow coverage would pass a self-test whose own list
# no longer contains the word. That is the exact failure mode this whole change exists
# to end -- "silently omit the class that is missing" -- reproduced inside the
# instrument meant to catch it.
#
# So the list the report is checked against is the PROBE's, parsed from its source. The
# two directions both bite: a class dropped from $COVERAGE_CLASSES is missing from the
# report and is named in the probe's source, and a class added to the probe is absent
# from the report and from $COVERAGE_CLASSES. The pattern is anchored on the table's
# own `{ "..."` shape rather than on a bare word, so it does not pick up the prose that
# names these classes in the comments above it.
#
# POSIX BRE throughout (`\{1,\}`, not `+`), because this script has to print its own
# help and run its own self-test on a BSD sed as well as a GNU one.
probe_declared_classes() {
    local f="$root/tests/integration/asan_coverage_probe.c"

    if [ ! -f "$f" ]; then
        return 1
    fi
    sed -n 's/^[[:space:]]*{ "\([a-z-]\{1,\}\)", .*/\1/p' "$f"
}

# report_selftest: render the report from canned inputs and assert the rendered text
# carries what the report is for. Returns 0 or 1, printing the reason on failure.
#
# WHAT THIS IS NOT: it does not run a container, a build or a sanitizer. It checks the
# SHAPE of the report, which is the half that can silently lose a section in an edit
# and the half that two minutes of container time would never get re-checked for. The
# other half -- that the classes really are watched in this image -- is what the probe
# run inside the container is for, and this file's other teeth run it there.
report_selftest() {
    local out ledger declared i c fail=0

    ledger=""
    for c in $COVERAGE_CLASSES; do
        if [ "$c" = "stack-use-after-return" ]; then
            ledger="${ledger}COVER $c NOT-COVERED (canned: the case ran and AddressSanitizer reported nothing for it)
"
        else
            ledger="${ledger}COVER $c PROVED
"
        fi
    done

    # The canned strings carry NO test counts, and that is deliberate rather than
    # incidental: this is a SHIPPED SCRIPT, check-docs-truth.py reads the prose in it,
    # and a canned "out of 100" here would be a test-count claim that has nothing to
    # do with this tree. The self-test is about the report's shape, so the numbers in
    # it are not the point.
    out=$( render_report "Release" "$ledger" "canned totals line" \
                         "canned findings line" 2>&1 )

    case "$out" in
        *"build type"*) ;;
        *) echo "gate-linux-cell.sh --report-selftest: FAIL -- the report does not name the BUILD TYPE, so a green result reads as configuration-independent" >&2; fail=1 ;;
    esac
    case "$out" in
        *"sanitizer coverage"*) ;;
        *) echo "gate-linux-cell.sh --report-selftest: FAIL -- the report carries NO COVERAGE STATEMENT: a findings count beside nothing that says what was watched is the failure this pass exists to end" >&2; fail=1 ;;
    esac
    case "$out" in
        *"SANITIZER COVERAGE INCOMPLETE"*) ;;
        *) echo "gate-linux-cell.sh --report-selftest: FAIL -- an unproved class did not produce the loud banner" >&2; fail=1 ;;
    esac
    case "$out" in
        *"report-complete:"*) ;;
        *) echo "gate-linux-cell.sh --report-selftest: FAIL -- the report has no machine-readable completeness marker, so a report that lost its coverage statement would look like any other" >&2; fail=1 ;;
    esac
    case "$out" in
        *"coverage=INCOMPLETE"*) ;;
        *) echo "gate-linux-cell.sh --report-selftest: FAIL -- the completeness marker does not record the incomplete state" >&2; fail=1 ;;
    esac
    # EVERY class must be named -- and the list is the PROBE's, read from its source,
    # not this file's. See probe_declared_classes(): with this file's own list, a class
    # dropped from COVERAGE_CLASSES would delete the check on it, which is the defect
    # this pass exists to end, rebuilt inside the instrument meant to catch it.
    declared=$(probe_declared_classes) || declared=""
    if [ -z "$declared" ]; then
        echo "gate-linux-cell.sh --report-selftest: FAIL -- could not read the class list" \
             "out of tests/integration/asan_coverage_probe.c, so the cross-check between" \
             "what the probe proves and what the report claims did not run. Not skipping" \
             "it: a cross-check that silently cannot run is the decorative check again." >&2
        fail=1
    fi
    for c in $declared; do
        i=$(printf '%s\n' "$out" | grep -c -- "$c" || true)
        if [ "$i" = "0" ]; then
            echo "gate-linux-cell.sh --report-selftest: FAIL -- the probe proves '$c' but the report does not name it, so the report under-claims and the self-test's own list would not have noticed" >&2
            fail=1
        fi
    done
    # EVERY class in this file's list must be one the probe actually proves. The other
    # direction: a class named here that the probe does not provoke is a coverage claim
    # with nothing behind it, which is the ORIGINAL defect wearing a different hat.
    for c in $COVERAGE_CLASSES; do
        printf '%s\n' "$declared" | grep -q -- "$c" || {
            echo "gate-linux-cell.sh --report-selftest: FAIL -- COVERAGE_CLASSES claims '$c' but tests/integration/asan_coverage_probe.c does not provoke it: a class that is named and not watched" >&2
            fail=1
        }
    done
    # A report that lists three of four is the shape of "silently omit the one that is
    # missing", which is what must never happen.
    for c in $COVERAGE_CLASSES; do
        i=$(printf '%s\n' "$out" | grep -c -- "$c" || true)
        if [ "$i" = "0" ]; then
            echo "gate-linux-cell.sh --report-selftest: FAIL -- the report does not name the '$c' class at all" >&2
            fail=1
        fi
    done
    # And the COMPLETE case must still carry every class, so the check cannot be
    # satisfied by a report that only ever renders the unproved branch.
    out=$( render_report "Release" "$(printf 'COVER %s PROVED\n' $COVERAGE_CLASSES)" \
                         "canned totals line" "canned findings line" 2>&1 )
    for c in $COVERAGE_CLASSES; do
        i=$(printf '%s\n' "$out" | grep -c -- "$c" || true)
        if [ "$i" = "0" ]; then
            echo "gate-linux-cell.sh --report-selftest: FAIL -- the all-proved report does not name '$c'" >&2
            fail=1
        fi
    done
    case "$out" in
        *"coverage=complete"*) ;;
        *) echo "gate-linux-cell.sh --report-selftest: FAIL -- the all-proved report does not record coverage=complete" >&2; fail=1 ;;
    esac
    case "$out" in
        *"SANITIZER COVERAGE INCOMPLETE"*)
            echo "gate-linux-cell.sh --report-selftest: FAIL -- the all-proved report still prints the incomplete banner" >&2; fail=1 ;;
        *) ;;
    esac

    if [ "$fail" != "0" ]; then
        return 1
    fi
    echo "gate-linux-cell.sh --report-selftest: OK -- the report names its build type, states its coverage per class, and marks itself complete or incomplete."
    return 0
}

if [ "$RENDER" = "1" ]; then
    # No docker, no Linux, no build, like --report-selftest: both of these describe a
    # piece of this file rather than run this cell.
    render_report "$BUILD_TYPE" "$(grep '^COVER ' || true)" \
                  "totals: not rendered here -- this reads a coverage ledger only" \
                  "findings: not rendered here -- this reads a coverage ledger only"
    exit $?
fi

if [ "$SELFTEST" = "1" ]; then
    # Before every refusal below, on purpose: this one needs no docker, no Linux and
    # no build, and a self-test that skipped on macOS would only ever run on the
    # machine whose report is least in question.
    report_selftest
    exit $?
fi

# The three outcomes, as names. Named so the words cannot drift between the places that
# produce them and the place that prints them.
RC_PASS=0
RC_FAIL=1
RC_SKIP=3

IMAGE="${GATE_LINUX_IMAGE:-ircserve-lsan:bookworm}"
JOBS="${GATE_LINUX_JOBS:-$( (command -v nproc >/dev/null 2>&1 && nproc) || echo 4)}"

# Why it did not run. Printed by the caller, so it has to be a string on stdout.
skip_reason() {
    echo "$1"
    exit "$RC_SKIP"
}

# --- the refusals, each with the reason it is a REFUSAL and not a fallback ---------
# There is no fallback. Every alternative to running this on Linux is a different
# check, and the history at the top of this file is a list of the defects a
# substitute check missed.
case "$(uname -s)" in
    Linux) ;;
    *) skip_reason "this cell must run on Linux: it is $(uname -s), and LeakSanitizer,
glibc's __wur and ASan's stack-use-after-return default have no equivalent here" ;;
esac
command -v docker >/dev/null 2>&1 || skip_reason "docker is not on PATH, so there is
no way to reach a glibc userspace from this machine"
docker info >/dev/null 2>&1 || skip_reason "the docker daemon is not reachable
(docker info failed); the cell reports that it did not run rather than passing"
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    skip_reason "the image $IMAGE is not present locally. Build it with:
  docker build -t $IMAGE - <<'DOCKERFILE'
  FROM debian:bookworm
  RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \\
      --no-install-recommends build-essential cmake libssl-dev python3 ca-certificates \\
      && rm -rf /var/lib/apt/lists/*
  WORKDIR /build
  DOCKERFILE
Then re-run. The cell does not build the image itself: an image build is minutes of
network, and a cell that silently spends them is a cell whose duration nobody predicted."
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/irc-serve-lsacell.XXXXXX") \
    || skip_reason "mktemp -d failed, so there is no scratch tree to build in"
cleanup() {
    if [ "$KEEP" = "1" ]; then
        echo "gate-linux-cell.sh: scratch tree kept at $work" >&2
        docker run --rm -v "$work:/w" "$IMAGE" true >/dev/null 2>&1 || true
        return
    fi
    # The build runs in a container as root, so the tree is root-owned and this user
    # cannot remove it with rm. THAT is the only reason for the container round trip,
    # and skipping it leaves a root-owned directory behind for every failed run -- at
    # which point the second failure of a debugged script is a permission error that
    # looks like the bug.
    docker run --rm -v "$work:/w" "$IMAGE" rm -rf /w >/dev/null 2>&1 || rm -rf "$work" || true
}
trap cleanup EXIT

# The tree, copied rather than bind-mounted. Two reasons, both measured:
#   * a container's build writes obj-*/ and Testing/ into the source tree, which would
#     leave root-owned directories in the developer's checkout;
#   * a bind mount of the working tree means the container's gcc and the host's cmake
#     disagree about file ownership, and `ctest` writes its own logs there.
# The copy is `git archive`, so it is the COMMITTED tree -- the same thing CI builds and
# the same thing the .orig.tarball is made from. It also means this cell cannot be
# affected by an uncommitted local change, which is a feature for a gate: it answers
# "does the commit build on Linux", not "does this checkout build on Linux".
rsync -a --exclude '.git' --exclude 'build-gate' --exclude '__pycache__' \
      "$root/" "$work/irc-serve/" 2>/dev/null \
    || skip_reason "could not copy the tree into a scratch directory"

echo "irc-serve Linux cell (glibc, ASan + LSan + UBSan)"
echo "  source      : $root"
echo "  scratch     : $work"
echo "  image       : $IMAGE"
echo "  build type  : $BUILD_TYPE  (a sanitizer result is a claim about THIS build;"
echo "                -O3 can delete an allocation, so it is not configuration-"
echo "                independent -- see the header and tests/integration/lsan_probe.c)"
echo "  ASAN_OPTIONS: $ASAN_RUN_OPTS"
echo "  build -j    : $JOBS"
echo "  probe       : $( [ "$PROBE" = "1" ] && echo ON || echo OFF)"
echo

# --- the two TLS configurations ---------------------------------------------------
# NOT ONE. A WITH_TLS=OFF build compiles zero tokens of OpenSSL, so it says nothing
# about glibc+OpenSSL, and glibc's TLS paths are a different library from its libc.
total_fail=0
ran=0
# cov_fail COUNTS CONFIGS WHOSE COVERAGE WAS NOT PROVED, and it is separate from
# total_fail on purpose. A run whose suite is green and whose coverage was not proved
# is a different fact from a run that found a defect, and collapsing the two would
# make the first unreadable -- which is the report this file used to produce, where
# both came out as "0 findings".
cov_fail=0
cfg_cov_incomplete=0

for tls in OFF ON; do
    d="$work/irc-serve/build-linux-tls$tls"
    echo "--- WITH_TLS=$tls: configure"
    if ! docker run --rm -v "$work:/build" -w /build/irc-serve "$IMAGE" \
            cmake -B "build-linux-tls$tls" -S . \
                  -DCMAKE_BUILD_TYPE=Release \
                  -DBUILD_TESTING=ON \
                  -DWITH_TLS="$tls" \
                  -DIRC_SANITIZE=ON \
                  -DIRC_LSAN_PROBE="$PROBE" \
            > "$d.cfg.log" 2>&1; then
        echo "    CONFIGURE FAILED"
        tail -n 12 "$d.cfg.log" | sed 's/^/      /'
        total_fail=$((total_fail + 1))
        continue
    fi
    ran=$((ran + 1))

    echo "--- WITH_TLS=$tls: build"
    if ! docker run --rm -v "$work:/build" -w /build/irc-serve "$IMAGE" \
            cmake --build "build-linux-tls$tls" --parallel "$JOBS" \
            > "$d.build.log" 2>&1; then
        echo "    BUILD FAILED"
        grep -m8 -E 'error:|warning:' "$d.build.log" | sed 's/^/      /'
        total_fail=$((total_fail + 1))
        continue
    fi
    # Warnings COUNTED, not just exit-coded, exactly as the macOS cells do: a build can
    # succeed and still print warnings from a path the flag set does not cover, and on
    # Linux that path is a different compiler with a different diagnostic set.
    local_errs=$(grep -c 'error:' "$d.build.log" || true)
    local_warns=$(grep -c 'warning:' "$d.build.log" || true)
    printf '    0 errors 0 warnings check: errors=%s warnings=%s\n' \
        "$local_errs" "$local_warns"
    if [ "$local_errs" != "0" ] || [ "$local_warns" != "0" ]; then
        grep -m8 -E 'error:|warning:' "$d.build.log" | sed 's/^/      /'
        total_fail=$((total_fail + 1))
        continue
    fi

    # The ASAN_OPTIONS this cell passes, written out in full and in ONE place, so
    # that "the cell watched X" has exactly one answer in the file. See the header
    # for why detect_stack_use_after_return=1 is here and was not before.
    echo "--- WITH_TLS=$tls: ctest under ASAN_OPTIONS=$ASAN_RUN_OPTS UBSAN_OPTIONS=halt_on_error=1"
    # The options are passed as -e to the CONTAINER, so they reach the ctest process
    # inside it. Setting them on the host's docker command line would set them for
    # docker itself, which is the exact substitution that makes a gate report a leak
    # check that never ran.
    ctest_rc=0
    docker run --rm \
            -e ASAN_OPTIONS="$ASAN_RUN_OPTS" \
            -e UBSAN_OPTIONS=halt_on_error=1 \
            -v "$work:/build" -w /build/irc-serve "$IMAGE" \
            ctest --test-dir "build-linux-tls$tls" -j "$JOBS" --timeout 300 \
                  --output-on-failure \
            > "$d.test.log" 2>&1 || ctest_rc=$?

    # The three sanitizer signatures, COUNTED. A count is what makes "there is no
    # leak" a measurement rather than an impression: a log that contains the word
    # LeakSanitizer once is a different fact from a log that contains it zero times,
    # and only the number distinguishes a clean run from a run nobody read.
    #
    # --output-on-failure ABOVE IS WHAT MAKES THESE COUNTS MEAN ANYTHING, and that
    # was measured rather than assumed: without it, ctest prints only the summary
    # line for a failed test and writes each test's own output to
    # Testing/Temporary/LastTest.log. The first version of this cell had no
    # --output-on-failure, and a fault-injected 4 KiB leak in server_init() made it
    # fail correctly while printing
    #     ERROR: LeakSanitizer   0
    #     ERROR: AddressSanitizer 0
    #     UBSan runtime error    0
    # -- three zeros under a heading that says "sanitizer findings", which is worse
    # than printing nothing. A count of findings in a log that does not contain the
    # findings is a count of nothing.
    findings="LeakSanitizer $(grep -c 'ERROR: LeakSanitizer' "$d.test.log" || true), AddressSanitizer $(grep -c 'ERROR: AddressSanitizer' "$d.test.log" || true), UBSan $(grep -c 'runtime error:' "$d.test.log" || true)"

    # -------------------------------------------------------------------------
    # THE COVERAGE PROBE, run DIRECTLY and with the same options ctest was given.
    #
    # Directly rather than through ctest, and the reason is in tests/integration/
    # CMakeLists.txt: ctest reports one thing -- a test failed -- and here a failure
    # means "this image is not watching a class", which is a fact about the gate and
    # not about the software. Printing that as a red suite line would be the
    # misleading report this project keeps finding. So this runs beside ctest, with
    # the SAME -e ASAN_OPTIONS, and its verdict becomes the coverage statement.
    # -------------------------------------------------------------------------
    ledger=""
    if [ "$PROBE" = "1" ]; then
        cov_rc=0
        docker run --rm \
                -e ASAN_OPTIONS="$ASAN_RUN_OPTS" \
                -v "$work:/build" -w /build/irc-serve "$IMAGE" \
                "build-linux-tls$tls/tests/integration/asan_coverage_probe" \
                > "$d.cov.log" 2>&1 || cov_rc=$?
        # The probe's own COVER lines, VERBATIM. They are not re-derived here: a
        # verdict this script recomputed would be a verdict the probe does not have.
        ledger=$(grep '^COVER ' "$d.cov.log" || true)
        if [ -z "$ledger" ]; then
            # The probe produced no verdict at all, which is the worst case and must
            # not read as "nothing to report".
            for c in $COVERAGE_CLASSES; do
                ledger="${ledger}COVER $c NOT-COVERED (the probe produced no verdict at all; see build-linux-tls$tls/tests/integration/asan_coverage_probe output)
"
            done
            sed -n '1,20p' "$d.cov.log" | sed 's/^/      /'
        fi
        # The verdict is coverage_complete's, not this file's: "is there a NOT-COVERED
        # line" would pass a ledger that simply did not mention a class, and a class
        # that is not mentioned is exactly what this cell got wrong for its whole life.
        if [ "$cov_rc" != "0" ] || ! coverage_complete "$ledger"; then
            cfg_cov_incomplete=1
            cov_fail=$((cov_fail + 1))
        fi
    else
        # --no-probe, which exists for a developer bisecting a Linux-only failure.
        # It is NOT a way to get a green cell quietly: every class is recorded as
        # unproved, the banner fires, the trailer says coverage=INCOMPLETE and the
        # PASS line below says the coverage was not proved. What it does not do is
        # FAIL, because a bisect that has to be re-run with the probes on is a bisect
        # that gets abandoned.
        for c in $COVERAGE_CLASSES; do
            ledger="${ledger}COVER $c NOT-COVERED (--no-probe was given, so nothing was proved)
"
        done
        cfg_cov_incomplete=1
    fi

    totals=$(grep -oE '[0-9]+% tests passed(, [0-9]+ tests failed)? out of [0-9]+' \
             "$d.test.log" | head -1)
    [ -n "$totals" ] || totals="no totals line"

    if [ "$ctest_rc" != "0" ]; then
        echo "    TESTS FAILED"
        grep -E 'tests passed|tests failed out of|\*\*\*' "$d.test.log" \
            | head -8 | sed 's/^/      /'
        grep -m4 -E 'ERROR: LeakSanitizer|ERROR: AddressSanitizer|runtime error:' \
            "$d.test.log" | sed 's/^/      /'
        total_fail=$((total_fail + 1))
    fi

    # render_report decides completeness and prints the banner; the cell only has to
    # notice the exit status. cfg_cov_incomplete is kept for the final summary line.
    if render_report "$BUILD_TYPE" "$ledger" "$totals" "$findings"; then
        cfg_cov_incomplete=0
    else
        cfg_cov_incomplete=1
    fi

    if [ "$ctest_rc" != "0" ]; then
        continue
    fi
    echo "    ok: WITH_TLS=$tls"
done

echo
if [ "$ran" = "0" ]; then
    skip_reason "both configurations failed before ctest, so the cell produced no
result to report"
fi
# A coverage failure FAILS the cell, loudly. This is the decision and it is the strict
# one: the cell's entire reason to exist is the claim that it watched something, so a
# run in which it cannot show what it watched has not done its job and must not be
# green. The one escape is --no-probe, which is a developer's bisecting tool, is not
# the default, does not fail the cell, and leaves the INCOMPLETE banner and the
# coverage=INCOMPLETE trailer behind when it does.
if [ "$total_fail" != "0" ] || [ "$cov_fail" != "0" ]; then
    echo "GATE LINUX CELL: FAIL  ($total_fail configuration(s) failed, $cov_fail with unproved sanitizer coverage)"
    echo "logs: $work/irc-serve/build-linux-tls*.{cfg,build,test,cov}.log"
    echo "(re-run with --keep, or read them now -- --keep was not given, so they go"
    echo " when this script exits)"
    exit "$RC_FAIL"
fi
echo "GATE LINUX CELL: PASS  ($ran of 2 configurations, ASan + LSan + UBSan)"
# NAMED MACHINE AND TOOLCHAIN, and the sentence below is the scope of the claim
# rather than decoration: the numbers above were produced by ONE gcc in ONE pinned
# image, and a second toolchain's libasan is a different implementation of the same
# checks, so this is not the whole of what a sanitizer can say about this tree.
echo "MEASURED ON: $(uname -sr), $(docker run --rm "$IMAGE" sh -c 'cat /etc/debian_version 2>/dev/null' 2>/dev/null || echo 'debian bookworm'), gcc $(docker run --rm "$IMAGE" gcc -dumpfullversion 2>/dev/null || echo '?')"
echo "COVERAGE CLAIM: $cov_fail of $ran configurations with an unproved class; every ASan error"
echo "  class this cell names was proved live by a deliberate finding in this run, under"
echo "  ASAN_OPTIONS=$ASAN_RUN_OPTS, in a $BUILD_TYPE build. A different image or a"
echo "  different ASAN_OPTIONS is a different claim and this cell does not carry it."
exit "$RC_PASS"