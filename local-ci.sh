#!/bin/bash
# local-ci.sh — mirrors .github/workflows/ci.yml (ci_test job).
# Use plain `cmake`/`ctest`; mise.toml [env] prepends mise shims to PATH
# so the pinned toolchain resolves without a `mise run cmake` task.
set -euo pipefail

# Timeout (seconds) for each ctest run; override via CTEST_TIMEOUT.
CTEST_TIMEOUT=${CTEST_TIMEOUT:-60}

# Bail with a clear message if a required tool is missing.
for tool in cmake ctest git; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "[local-ci] ERROR: required tool '$tool' not found in PATH" >&2
        exit 1
    fi
done

# nproc is optional (not present on every platform); default to a safe value.
if command -v nproc >/dev/null 2>&1; then
    NPROC=$(nproc)
else
    echo "[local-ci] WARNING: nproc not found; defaulting to 4 jobs" >&2
    NPROC=4
fi

# Guard git rev-parse failure with a clear message.
if ! BRANCH=$(git rev-parse --abbrev-ref HEAD); then
    echo "[local-ci] ERROR: could not determine current branch (git rev-parse failed)" >&2
    exit 1
fi
echo "[local-ci] Branch: $BRANCH"

BUILD_TYPE=${BUILD_TYPE:-Release}

# IRC_FORTIFY is forwarded so the fortify cell is a real cell rather than a
# claim: `IRC_FORTIFY=1 ./local-ci.sh` builds and runs the whole suite with
# -D_FORTIFY_SOURCE=2. Read CMakeLists.txt's IRC_FORTIFY comment before reading
# anything into what that catches -- on macOS it is a measured no-op, and this
# class of Linux-only diagnostic lives in glibc's declaration of read(), which no
# macOS build can see. It is NOT a substitute for the Linux CI job.
cmake -B build -S . -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" -DBUILD_TESTING=ON \
  -DIRC_FORTIFY="${IRC_FORTIFY:-OFF}"
cmake --build build --parallel "${NPROC}"
# -j matters: the suite is 61 independent processes and ctest defaults to one
# at a time, so serial execution spends most of the wall clock waiting. Override
# with CTEST_JOBS=1 when bisecting a failure, where interleaved output is worse
# than slow.
CTEST_JOBS="${CTEST_JOBS:-$( (command -v nproc >/dev/null && nproc) || sysctl -n hw.ncpu 2>/dev/null || echo 4)}"
# tee'd, and with pipefail already on, so ctest's own exit status is what fails
# the script. The log is then read by the skip gate below -- running the suite a
# second time to find out which tests skipped would double this script's cost for
# no new information.
CTEST_LOG="${BUILD_DIR:-build}/ctest-local.log"
ctest --test-dir build --output-on-failure --timeout "${CTEST_TIMEOUT}" -j "${CTEST_JOBS}" | tee "${CTEST_LOG}"

# The skip ratchet, run against the run that just happened. It FAILS if a test
# skips without a line in tests/known_skips.txt, and it also fails if a listed
# skip is no longer skipping -- the second direction is what stops the list
# becoming a permanent allowlist. It is not "zero skips": that is unreachable
# before Phase 9, and docs/SERVER_DESIGN.md 6.4 gives the argument. See
# docs/DEVELOPMENT.md, "The skip gate is a ratchet".
./scripts/check-skips.sh -b build "${CTEST_LOG}"
./scripts/check-attribution.sh
