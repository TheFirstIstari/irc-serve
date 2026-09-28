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

cmake -B build -S . -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" -DBUILD_TESTING=ON
cmake --build build --parallel "${NPROC}"
ctest --test-dir build --output-on-failure --timeout "${CTEST_TIMEOUT}"
