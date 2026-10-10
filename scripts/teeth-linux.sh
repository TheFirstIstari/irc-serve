#!/usr/bin/env bash
# teeth-linux.sh -- the faults that can only be run WHERE THE ANSWER EXISTS.
#
# WHY THIS FILE IS SEPARATE FROM scripts/teeth.sh
# ----------------------------------------------
# `scripts/teeth.sh` runs on the developer machine and builds Debug, WITHOUT
# sanitizers, because every fault in it is a source-level defect that a C test catches.
# The faults here are about a SANITIZER'S RUNTIME CONFIGURATION inside a pinned
# container, and there is no way to run them on macOS: LeakSanitizer does not exist
# there, and the question these faults ask -- "does this image's ASan actually watch
# stack-use-after-return" -- has a different answer on every platform, measured. Running
# them on macOS would be testing macOS's ASan and calling it the container's.
#
# IT IS ALSO NOT IN THE GATE, and for the same reason `scripts/teeth.sh` is not: it
# builds a sanitized tree inside a container, which is minutes of work per fault, and a
# gate that spends that on every invocation stops being run. It is the instrument for
# when somebody changes the cell's ASAN_OPTIONS, which is rare and consequential.
#
#   ./scripts/teeth-linux.sh                 both faults, on this machine
#   ./scripts/teeth-linux.sh --keep          leave the staged trees behind
#
# EXIT STATUS
# -----------
# 0 when every fault was caught and every control stayed green. 1 with a line per fault
# that was not caught. 3 when the cell could not run at all -- no docker, no image, not
# Linux -- which is a THIRD thing and is deliberately not 0 or 1, for the reason
# scripts/gate-linux-cell.sh's header gives at length: a check that reports success for
# work it did not do is the failure this project keeps finding.
#
# MEASURED ON: the machine and image each run prints in its own header. Nothing in this
# file claims an ASan result from any other machine.

set -uo pipefail   # NOT -e: every fault is reported, not aborted on.

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
root=$(cd -- "$here/.." && pwd)
TEETH="$here/teeth"
WORK="${WORK:-/tmp/teeth-linux}"

KEEP=0
while [ $# -gt 0 ]; do
    case "$1" in
        --keep) KEEP=1 ;;
        -h|--help) sed -n '2,32p' "$0"; exit 0 ;;
        *) echo "teeth-linux.sh: unknown argument '$1'" >&2; exit 2 ;;
    esac
    shift
done

PASS=0
FAIL=0
FAILED_LIST=""

note() { printf '%s\n' "$*"; }

IMAGE="${GATE_LINUX_IMAGE:-ircserve-lsan:bookworm}"

# --- the three outcomes, as in gate-linux-cell.sh ------------------------------------
case "$(uname -s)" in
    Linux) ;;
    *) note "teeth-linux.sh: SKIP -- this must run on Linux; it is $(uname -s)."; exit 3 ;;
esac
command -v docker >/dev/null 2>&1 || { note "teeth-linux.sh: SKIP -- no docker on PATH"; exit 3; }
docker info >/dev/null 2>&1 || { note "teeth-linux.sh: SKIP -- the docker daemon is not reachable"; exit 3; }
docker image inspect "$IMAGE" >/dev/null 2>&1 || { note "teeth-linux.sh: SKIP -- the image $IMAGE is not present locally; scripts/gate-linux-cell.sh says how to build it"; exit 3; }

note "teeth-linux: host $(uname -sr), image $IMAGE, gcc $(docker run --rm "$IMAGE" gcc -dumpfullversion 2>/dev/null || echo '?')"
note "teeth-linux: scratch $WORK"
note

cleanup() {
    if [ "$KEEP" = "1" ]; then
        note "teeth-linux: scratch trees kept at $WORK"
        return
    fi
    # EVERY staged tree, not just the fault ones: the control's build is also made by
    # the container as root, so a glob that skips it leaves a root-owned directory that
    # makes the SECOND run's cleanup the thing that fails.
    for d in "$WORK"/*; do
        [ -d "$d" ] || continue
        docker run --rm -v "$d:/w" "$IMAGE" rm -rf /w >/dev/null 2>&1 || rm -rf "$d" || true
    done
    rmdir "$WORK" 2>/dev/null || true
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# One fault: stage the tree, apply the fault, build it SANITIZED, and require the
# cell's own probe to go red AND the cell's own report to change.
#
# WHY IT READS ASAN_RUN_OPTS OUT OF THE (POSSIBLY FAULTED) SCRIPT. The fault under
# test is one word in that variable, so re-typing the options here would prove this
# script's own copy of them. Everything the tooth asserts -- the options, the probe's
# verdict, the report's text -- comes out of the faulted tree.
# ---------------------------------------------------------------------------
run_asan_option_fault() {
    local name=$1 script=$2 expect_class=$3
    local d="$WORK/fault-$name"

    rm -rf "$d"
    mkdir -p "$d"
    # `-P` for the reason scripts/teeth.sh's stage_tree gives at length: `debian` is a
    # tracked symlink to `packaging/debian`, and a bare `cp` of it fails and takes the
    # staging step down with it. The link is relative, so it resolves in the staged copy.
    (cd "$root" && git ls-files -z | while IFS= read -r -d '' f; do
        mkdir -p "$d/$(dirname "$f")"
        cp -P "$root/$f" "$d/$f"
    done)

    if ! (cd "$d" && python3 "$TEETH/$script"); then
        note "FAULT NOT APPLIED: $name ($script)"
        FAIL=$((FAIL + 1)); FAILED_LIST="$FAILED_LIST $name(apply)"; return
    fi

    note "--- $name: sanitized build in $IMAGE"
    if ! docker run --rm -v "$d:/build" -w /build "$IMAGE" \
            sh -c 'cmake -B b -S . -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON \
                     -DWITH_TLS=OFF -DIRC_SANITIZE=ON -DIRC_LSAN_PROBE=ON \
                     && cmake --build b --parallel '"${JOBS:-8}" >"$d.build.log" 2>&1; then
        note "FAULT $name DID NOT BUILD -- a fault that does not build proves nothing"
        tail -6 "$d.build.log" 2>/dev/null | sed 's/^/      /'
        FAIL=$((FAIL + 1)); FAILED_LIST="$FAILED_LIST $name(build)"; return
    fi

    # 0 errors / 0 warnings counted on the BUILD LOG, and the probe binary newer than
    # every source -- the same two gates scripts/teeth.sh applies, for the same reason:
    # a stale object file that passes is the one way this file can report a success
    # that means nothing.
    local errs warns
    errs=$(grep -c 'error:' "$d.build.log" || true)
    warns=$(grep -c 'warning:' "$d.build.log" || true)
    note "    build: errors=$errs warnings=$warns"
    if [ "$errs" != "0" ] || [ "$warns" != "0" ]; then
        grep -m6 -E 'error:|warning:' "$d.build.log" | sed 's/^/      /'
        FAIL=$((FAIL + 1)); FAILED_LIST="$FAILED_LIST $name(build:$errs/$warns)"; return
    fi
    local probe="$d/b/tests/integration/asan_coverage_probe"
    if [ ! -x "$probe" ]; then
        note "FAULT $name: the coverage probe was not built at all, so there is nothing to run"
        FAIL=$((FAIL + 1)); FAILED_LIST="$FAILED_LIST $name(noprobe)"; return
    fi
    local newest_src
    newest_src=$(find "$d" -name '*.c' -o -name '*.h' | xargs ls -t 2>/dev/null | head -1)
    if [ "$newest_src" -nt "$probe" ]; then
        note "FAULT $name: the probe binary is NOT newer than the newest source"
        FAIL=$((FAIL + 1)); FAILED_LIST="$FAILED_LIST $name(stale)"; return
    fi
    note "    probe binary is newer than every source in the staged tree"

    # The options, read out of the faulted tree.
    local opts
    opts=$(sed -n 's/^ASAN_RUN_OPTS="\(.*\)"$/\1/p' "$d/scripts/gate-linux-cell.sh" | head -1)
    if [ -z "$opts" ]; then
        note "FAULT $name: ASAN_RUN_OPTS was not readable from the faulted script"
        FAIL=$((FAIL + 1)); FAILED_LIST="$FAILED_LIST $name(noopts)"; return
    fi
    note "    ASAN_OPTIONS from the faulted cell: $opts"

    local rc=0
    docker run --rm -e ASAN_OPTIONS="$opts" -v "$d:/build" -w /build "$IMAGE" \
        b/tests/integration/asan_coverage_probe >"$d.probe.log" 2>&1 || rc=$?
    note "    probe exit=$rc"
    grep -E '^COVER ' "$d.probe.log" | sed 's/^/      /'

    if [ "$rc" = "0" ]; then
        note "FAULT $name NOT CAUGHT: the probe is still GREEN with these options"
        FAIL=$((FAIL + 1)); FAILED_LIST="$FAILED_LIST $name(green)"; return
    fi
    if ! grep -Fq "COVER $expect_class NOT-COVERED" "$d.probe.log"; then
        note "FAULT $name NOT CAUGHT FOR THE RIGHT REASON: no 'COVER $expect_class NOT-COVERED'"
        FAIL=$((FAIL + 1)); FAILED_LIST="$FAILED_LIST $name(wrongclass)"; return
    fi

    # AND THE CELL'S OWN REPORT MUST CHANGE. Rendered by the FAULTED tree's own
    # --report-render, from the probe's real output -- not by a reimplementation here.
    if (cd "$d" && sh scripts/gate-linux-cell.sh --report-render <"$d.probe.log" \
            >"$d.report.log" 2>&1); then
        note "FAULT $name NOT CAUGHT: the cell's report still claims complete coverage"
        FAIL=$((FAIL + 1)); FAILED_LIST="$FAILED_LIST $name(reportgreen)"; return
    fi
    if ! grep -Fq 'SANITIZER COVERAGE INCOMPLETE' "$d.report.log"; then
        note "FAULT $name: the report changed but did not print the incomplete banner"
        sed -n '1,16p' "$d.report.log" | sed 's/^/      /'
        FAIL=$((FAIL + 1)); FAILED_LIST="$FAILED_LIST $name(reportquiet)"; return
    fi
    grep -E 'report-complete:' "$d.report.log" | sed 's/^/      /'

    note "ok: $name -> the probe went red on '$expect_class' and the cell's report went INCOMPLETE"
    PASS=$((PASS + 1))
}

# ---------------------------------------------------------------------------
# THE POSITIVE CONTROL, and it is not optional.
#
# A tooth that only ever runs faults proves it can detect the fault it was written for.
# It does not prove it could tell that fault from any other red, and the cheapest way
# to be sure the probe is reading the options at all is to run it with the options the
# SHIPPED cell passes and require it GREEN. So this runs first, on the unmutated tree,
# and if it is red then nothing after it means anything.
#
# It also answers the question the whole toolchain decision turned on, every time
# somebody re-runs this: does THIS image watch all four classes with the options the
# cell actually passes? The answer is printed, with the image and the gcc, so it is a
# dated measurement rather than a claim in a comment.
# ---------------------------------------------------------------------------
control_green() {
    local d="$WORK/control-green"

    rm -rf "$d"
    mkdir -p "$d"
    # `-P` for the reason scripts/teeth.sh's stage_tree gives at length: `debian` is a
    # tracked symlink to `packaging/debian`, and a bare `cp` of it fails and takes the
    # staging step down with it. The link is relative, so it resolves in the staged copy.
    (cd "$root" && git ls-files -z | while IFS= read -r -d '' f; do
        mkdir -p "$d/$(dirname "$f")"
        cp -P "$root/$f" "$d/$f"
    done)
    if ! docker run --rm -v "$d:/build" -w /build "$IMAGE" \
            sh -c 'cmake -B b -S . -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON \
                     -DWITH_TLS=OFF -DIRC_SANITIZE=ON -DIRC_LSAN_PROBE=ON \
                     && cmake --build b --parallel '"${JOBS:-8}" >"$d.build.log" 2>&1; then
        note "CONTROL DID NOT BUILD"
        tail -6 "$d.build.log" 2>/dev/null | sed 's/^/      /'
        FAIL=$((FAIL + 1)); FAILED_LIST="$FAILED_LIST control(build)"; return
    fi
    local errs warns
    errs=$(grep -c 'error:' "$d.build.log" || true)
    warns=$(grep -c 'warning:' "$d.build.log" || true)
    note "--- control: build errors=$errs warnings=$warns"
    if [ "$errs" != "0" ] || [ "$warns" != "0" ]; then
        FAIL=$((FAIL + 1)); FAILED_LIST="$FAILED_LIST control(build:$errs/$warns)"; return
    fi
    local probe="$d/b/tests/integration/asan_coverage_probe"
    local newest_src
    newest_src=$(find "$d" -name '*.c' -o -name '*.h' | xargs ls -t 2>/dev/null | head -1)
    if [ ! -x "$probe" ] || [ "$newest_src" -nt "$probe" ]; then
        note "CONTROL: no fresh probe binary at $probe"
        FAIL=$((FAIL + 1)); FAILED_LIST="$FAILED_LIST control(noprobe)"; return
    fi
    local opts rc=0
    opts=$(sed -n 's/^ASAN_RUN_OPTS="\(.*\)"$/\1/p' "$root/scripts/gate-linux-cell.sh" | head -1)
    note "--- control: ASAN_OPTIONS from the SHIPPED cell: $opts"
    docker run --rm -e ASAN_OPTIONS="$opts" -v "$d:/build" -w /build "$IMAGE" \
        b/tests/integration/asan_coverage_probe >"$d.probe.log" 2>&1 || rc=$?
    grep -E '^COVER |classes proved' "$d.probe.log" | sed 's/^/      /'
    note "    probe exit=$rc"
    if [ "$rc" != "0" ]; then
        note "CONTROL RED: the SHIPPED cell's own options do not watch every class in this"
        note "  image. Every result below would then be ambiguous, so the run stops here."
        FAIL=$((FAIL + 1)); FAILED_LIST="$FAILED_LIST control(red)"; return
    fi
    if ! (cd "$root" && sh scripts/gate-linux-cell.sh --report-render <"$d.probe.log" \
            >"$d.report.log" 2>&1); then
        note "CONTROL RED: the cell's own report did not come out complete"
        FAIL=$((FAIL + 1)); FAILED_LIST="$FAILED_LIST control(reportred)"; return
    fi
    grep -E 'report-complete:' "$d.report.log" | sed 's/^/      /'
    note "ok: control -> all classes proved with the shipped options, report complete"
    PASS=$((PASS + 1))
}

control_green

run_asan_option_fault asan-use-after-return-option-dropped \
    asan_use_after_return_option_dropped.py \
    stack-use-after-return

note
if [ "$FAIL" != "0" ]; then
    note "teeth-linux: $PASS of $((PASS + FAIL)) checks passed, $FAIL did not."
    note "not caught:$FAILED_LIST"
    exit 1
fi
note "teeth-linux: $PASS of $((PASS + FAIL)) checks passed, 0 did not."
exit 0