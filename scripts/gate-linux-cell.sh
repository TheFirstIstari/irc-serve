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
#   -DIRC_LSAN_PROBE=ON            builds tests/integration/lsan_probe.c, the test that
#                                  deliberately leaks and FAILS unless LSan reports it
#   -DCMAKE_BUILD_TYPE=Release     the configuration the .deb ships and the one CI runs
#   -DWITH_TLS=OFF and =ON         BOTH, because glibc's TLS stack is a different
#                                  library from its libc and one of the five historical
#                                  defects was in it
#   -DBUILD_TESTING=ON             without it there is nothing to run
#
# AND ASAN_OPTIONS=detect_leaks=1 is set by the RUN, not by the build, because
# LeakSanitizer is a runtime switch. That distinction is the whole point: an ASan binary
# that is merely linked against libasan reports memory errors and reports nothing about
# leaks, and a gate that confuses "built with sanitizers" with "ran leak detection" is
# the suppressed-check failure in its most respectable disguise.
#
# COST, WHICH IS REAL AND IS NOT HIDDEN: two full builds of 100 tests plus one
# executable, in a container, on a machine with 32 cores this is about two minutes. It
# is opt-in at the gate level (--linux) precisely because of that: it is the most
# expensive cell in the gate by a wide margin and it is the only one that can see a
# leak.

set -uo pipefail   # NOT -e: every failure below is reported, not aborted on.

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
root=$(cd -- "$here/.." && pwd)

KEEP=0
PROBE=1
while [ $# -gt 0 ]; do
    case "$1" in
        --keep)     KEEP=1 ;;
        --no-probe) PROBE=0 ;;
        -h|--help)  sed -n '2,80p' "$0"; exit 0 ;;
        *) echo "gate-linux-cell.sh: unknown argument '$1'" >&2; exit 2 ;;
    esac
    shift
done

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
echo "  build -j    : $JOBS"
echo "  probe       : $( [ "$PROBE" = "1" ] && echo ON || echo OFF)"
echo

# --- the two TLS configurations ---------------------------------------------------
# NOT ONE. A WITH_TLS=OFF build compiles zero tokens of OpenSSL, so it says nothing
# about glibc+OpenSSL, and glibc's TLS paths are a different library from its libc.
total_fail=0
ran=0

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

    echo "--- WITH_TLS=$tls: ctest under ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1"
    # The options are passed as -e to the CONTAINER, so they reach the ctest process
    # inside it. Setting them on the host's docker command line would set them for
    # docker itself, which is the exact substitution that makes a gate report a leak
    # check that never ran.
    if ! docker run --rm \
            -e ASAN_OPTIONS=detect_leaks=1 \
            -e UBSAN_OPTIONS=halt_on_error=1 \
            -v "$work:/build" -w /build/irc-serve "$IMAGE" \
            ctest --test-dir "build-linux-tls$tls" -j "$JOBS" --timeout 300 \
            > "$d.test.log" 2>&1; then
        echo "    TESTS FAILED"
        grep -E 'tests passed|tests failed out of|\*\*\*' "$d.test.log" \
            | head -8 | sed 's/^/      /'
        # The three sanitizer signatures, COUNTED. A count is what makes "there is no
        # leak" a measurement rather than an impression: a log that contains the word
        # LeakSanitizer once is a different fact from a log that contains it zero times,
        # and only the number distinguishes a clean run from a run nobody read.
        echo "    sanitizer findings:"
        printf '      ERROR: LeakSanitizer   %s\n' "$(grep -c 'ERROR: LeakSanitizer' "$d.test.log" || true)"
        printf '      ERROR: AddressSanitizer %s\n' "$(grep -c 'ERROR: AddressSanitizer' "$d.test.log" || true)"
        printf '      UBSan runtime error    %s\n' "$(grep -c 'runtime error:' "$d.test.log" || true)"
        grep -m4 -E 'ERROR: LeakSanitizer|ERROR: AddressSanitizer|runtime error:' \
            "$d.test.log" | sed 's/^/      /'
        total_fail=$((total_fail + 1))
        continue
    fi

    totals=$(grep -oE '[0-9]+% tests passed(, [0-9]+ tests failed)? out of [0-9]+' \
             "$d.test.log" | head -1)
    echo "    ${totals:-no totals line}"
    printf '    sanitizer findings: LeakSanitizer %s, AddressSanitizer %s, UBSan %s\n' \
        "$(grep -c 'ERROR: LeakSanitizer' "$d.test.log" || true)" \
        "$(grep -c 'ERROR: AddressSanitizer' "$d.test.log" || true)" \
        "$(grep -c 'runtime error:' "$d.test.log" || true)"
    echo "    ok: WITH_TLS=$tls"
done

echo
if [ "$ran" = "0" ]; then
    skip_reason "both configurations failed before ctest, so the cell produced no
result to report"
fi
if [ "$total_fail" != "0" ]; then
    echo "GATE LINUX CELL: FAIL  ($total_fail of $ran configuration(s) failed)"
    echo "logs: $work/irc-serve/build-linux-tls*.{cfg,build,test}.log"
    echo "(re-run with --keep, or read them now -- --keep was not given, so they go"
    echo " when this script exits)"
    exit "$RC_FAIL"
fi
echo "GATE LINUX CELL: PASS  ($ran of 2 configurations, ASan + LSan + UBSan)"
echo "MEASURED ON: $(uname -sr), $(docker run --rm "$IMAGE" sh -c 'cat /etc/debian_version 2>/dev/null' 2>/dev/null || echo 'debian bookworm'), gcc $(docker run --rm "$IMAGE" gcc -dumpversion 2>/dev/null || echo '?')"
exit "$RC_PASS"