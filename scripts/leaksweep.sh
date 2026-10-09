#!/usr/bin/env bash
# leaksweep.sh -- macOS `leaks(1)` over every test binary.
#
# WHY THIS EXISTS, AND WHY IT IS NOT IN THE GATE
# ------------------------------------------------
# Linux CI's LeakSanitizer found a 64 KiB leak in this tree's test suite, on both
# sanitizer cells, and it was the only leak the suite had. Every macOS gate cell said
# nothing about it, because LeakSanitizer does not exist on Darwin -- which is now the
# fifth time the local gate could not see something Linux could, after glibc's `__wur`,
# a missing `<sys/wait.h>`, `memmem`, and `tf_done()`.
#
# `leaks(1)` DOES exist on Darwin and DOES report leaks at exit with an allocation
# trace, so the leak is measurable on this machine after all. It is not the same tool
# as LeakSanitizer and agreement is not guaranteed, but "the local gate cannot see
# leaks" was only ever true of the gate, not of the platform.
#
# WHY IT IS NOT GATED, AND THE MEASUREMENT THAT SETTLED IT
# ---------------------------------------------------------
# MEASURED on this machine, Release + WITH_TLS=ON, all 100 test binaries:
#
#     ./scripts/leaksweep.sh build/          10m25s wall, 100 measured, 0 leaking
#     scripts/gate-linux-cell.sh (cachyos)      ~30s wall, whole suite, 0 leaking
#
# The second line counts the suite plus the LeakSanitizer probe, which the Linux cell
# builds and this one does not, so there is deliberately no test count to compare
# against: `scripts/check-docs-truth.py` reads this file and a number here would be a
# count of a build configuration that is not the default one.
#
# Ten and a half minutes against thirty seconds, and the thirty-second one is the tool
# that SEES MORE. The three reasons this file used to give for staying out of the gate
# are now measurements, and one of them has changed:
#
#   * IT IS SLOW. Above: ten minutes is not a marginal cost on a gate that is already
#     thirteen fresh builds, and it is spent on the WEAKER of the two tools.
#   * IT IS DARWIN-ONLY, so gating on it would leave the one place that can see leaks
#     ungated by it -- which is backwards. That was the argument while the only other
#     leak check was a CI job nobody ran locally.
#   * IT COULD BE WRONG AND STILL BLOCK. Still true, and now redundant: a checker
#     whose false-positive rate is unknown has no business failing a build, and
#     LeakSanitizer is the checker with a known failure mode.
#
# WHAT CHANGED, AND IT IS THE WHOLE OF IT: `scripts/gate-linux-cell.sh` now runs the
# suite under ASan + LeakSanitizer + UBSan in a glibc container, in about half a minute.
# Before that cell existed this file was the only leak measurement a developer could
# run at all; now it is the slower, shallower one, and the argument for keeping it is
# that it works with no docker and no second machine.
#
# SO: NOT FOLDED INTO THE GATE, and NOT DELETED. It stays as the pre-push step it was
# always going to be, and the gate's answer to the same question is the Linux cell. The
# honest summary for anyone deciding whether to run either: on a Mac with no Linux host
# and no docker, run this; anywhere else, run `scripts/gate-linux-cell.sh`, which is
# faster and also measures the forked children this file cannot follow.
#
# WHAT IT IS FOR: a person, before a push, who has touched ownership AND has no Linux
# host. It is the local half of the pair, and the honest label on the pair is that
# LeakSanitizer is the oracle and this is corroboration -- and the oracle is now
# `scripts/gate-linux-cell.sh`, reachable from the gate itself with `--linux`, rather
# than a CI job that only exists on someone else's machine.
#
# WHAT IT DOES NOT SEE, stated rather than discovered:
#   * CHILDREN, ON THIS PLATFORM ONLY. `nf_spawn_inline*()` forks a child, and
#     `leaks --atExit` reports on the process it launched -- it does not follow the
#     fork, so an inline child's heap is not measured by the run below. Children
#     exec'd from `nf_spawn_binary()` DO return from main() normally and ARE measured.
#
#     THIS PARAGRAPH USED TO CLAIM THE OPPOSITE AND IT WAS TRUE WHEN IT WAS WRITTEN.
#     It said an inline child was not leak-checked by ANYTHING in this project,
#     because `nf_child_run()`'s caller used `_exit()` and `_exit()` skips the atexit
#     handler LeakSanitizer checks at. That is no longer true: the spawn path calls
#     `exit()` (tests/harness/node_fixture.c, "exit(), NOT _exit(), AND THIS IS THE
#     CHANGE THAT MAKES AN INLINE NODE LEAK-CHECKED AT ALL"), so on LINUX an
#     inline child's heap IS measured by LSan's own handler, and a child that leaks
#     makes `nf_stop()` return 23 rather than 0 -- which every test that asserts
#     `nf_stop(&node) == 0` is already asserting.
#
#     So the honest statement of the boundary is narrower than it was: Linux CI
#     measures the children, this script does not. It is still the case that this is
#     not a substitute, because a report this tool prints about a CHILD would have to
#     come from the parent, and nothing here attaches one.
#
#     WHAT THE ORACLE SAID, and it is a measurement rather than a claim. On
#     2026-10-08 (PR #146) the Linux `ci_sanitizers (ASan+UBSan) WITH_TLS=ON` cell ran
#     with `ASAN_OPTIONS: detect_leaks=1` and reported `100% tests passed, 0 tests
#     failed out of 100`, `check-skips: OK: 0 skipped`. The inline-spawning tests ran
#     in that cell and passed -- `test_fed_skick_log` (#65), `test_tls` (#88),
#     `test_control_bytes` (#92) -- so the handler ran over forked nodes and reported
#     NOTHING. ZERO INLINE-CHILD LEAKS, where before this path nothing measured them
#     at all. That is the deliverable: the measurement is live, and it is clean.
#
#     AND THE CONSEQUENCE, because it is the opposite of what a fault-injection pass
#     would report and it would be dishonest to imply otherwise: RESTORING `_exit()`
#     IS NOT RED ANYWHERE. Not locally, and not on CI either. `_exit()` does not cause
#     a failure -- it SUPPRESSES a check, and a suppressed check cannot report a leak
#     that is not there. With zero leaks measured, the two forms are
#     observationally identical, so no fault can distinguish them and this change is
#     verified BY MEASUREMENT rather than by teeth. It becomes fault-visible the
#     moment a child leaks and a test asserts `nf_stop(&node) == 0`, which is the
#     whole of the mechanism and is stated at node_fixture.c's `exit()` call.
#   * ANYTHING AFTER A CRASH. A test that aborts is not measured.
set -u
dir="${1:-}"
if [ -z "$dir" ] || [ ! -d "$dir/tests" ]; then
    echo "usage: $0 BUILD_DIR   (a configured build tree)" >&2
    exit 2
fi
if ! command -v leaks >/dev/null 2>&1; then
    echo "leaksweep: SKIP -- leaks(1) is a macOS tool and is not on PATH here." >&2
    echo "leaksweep: the oracle on this platform is Linux CI's LeakSanitizer." >&2
    exit 0
fi
total=0
bad=0
for b in "$dir"/tests/*/*; do
    [ -f "$b" ] && [ -x "$b" ] || continue
    case "$b" in *.a|*.d) continue;; esac
    name=$(basename "$b")
    total=$((total + 1))
    out=$(leaks --atExit -- "$b" 2>&1)
    line=$(printf '%s\n' "$out" | grep -oE '[0-9]+ leak[s]? for [0-9]+ total leaked bytes' | head -1)
    case "$line" in
        ""|0\ leak*|"0 leaks for 0 total leaked bytes")
            ;;
        *)
            bad=$((bad + 1))
            echo "leaksweep: $name: $line"
            printf '%s\n' "$out" | grep -E "ROOT LEAK|LEAK:" | head -6 | sed 's/^/    /'
            printf '%s\n' "$out" | grep -E "^ *[0-9]+ +[a-zA-Z_]" \
                | grep -vE 'libsystem|libc\+\+|CoreFoundation|^ *[0-9]+ +dyld' | head -6 | sed 's/^/    /'
            ;;
    esac
done
echo "leaksweep: $total test binaries measured, $bad leaking."
echo "leaksweep: forked INLINE children are not measured here -- leaks(1) does not"
echo "leaksweep: follow the fork. Linux CI's LeakSanitizer DOES measure them, through"
echo "leaksweep: the atexit handler the spawn path reaches with exit(), and it is the"
echo "leaksweep: oracle for this as well."
[ "$bad" = "0" ]
