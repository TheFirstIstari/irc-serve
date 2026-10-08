#!/usr/bin/env bash
# leaksweep.sh -- macOS `leaks(1)` over every test binary.
#
# WHY THIS EXISTS, AND WHY IT IS NOT IN THE GATE
# ------------------------------------------------
# Linux CI's LeakSanitizer found a 64 KiB leak in this tree's test suite, on both
# sanitizer cells, and it was the only leak in 98 tests. Every one of this project's
# thirteen local gate cells said nothing about it, because LeakSanitizer does not exist
# on Darwin -- which is now the fifth time the local gate could not see something Linux
# could, after glibc's `__wur`, a missing `<sys/wait.h>`, `memmem`, and `tf_done()`.
#
# `leaks(1)` DOES exist on Darwin and DOES report leaks at exit with an allocation
# trace, so the leak is measurable on this machine after all. It is not the same tool
# as LeakSanitizer and agreement is not guaranteed, but "the local gate cannot see
# leaks" was only ever true of the gate, not of the platform.
#
# WHY IT IS NOT GATED, and this is a decision rather than an omission:
#   * IT IS SLOW. 98 binaries, each forking children and running real sockets, is
#     minutes rather than seconds, and the gate is already thirteen fresh builds.
#   * IT IS DARWIN-ONLY. `leaks(1)` is a macOS tool. On the Linux CI job it does not
#     exist, so gating on it would leave the one place that CAN see leaks ungated by
#     it -- which is backwards.
#   * IT COULD BE WRONG AND STILL BLOCK. A checker whose false-positive rate is
#     unknown and which cannot run where the problem is has no business failing a
#     build. This is the same reasoning that keeps `audit-teardown.py`'s full
#     enumeration out of the gate and its `--strict` mode in it.
#
# WHAT IT IS FOR: a person, before a push, who has touched ownership. It is the local
# half of the pair, and the honest label on the pair is that Linux CI is the oracle
# and this is corroboration.
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
