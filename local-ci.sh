#!/bin/bash
# local-ci.sh — mirrors .github/workflows/ci.yml (ci_test job).
# Use plain `cmake`/`ctest`; mise.toml [env] prepends mise shims to PATH
# so the pinned toolchain resolves without a `mise run cmake` task.
set -euo pipefail
BRANCH=$(git rev-parse --abbrev-ref HEAD)
echo "[local-ci] Branch: $BRANCH"

BUILD_TYPE=${BUILD_TYPE:-Release}
NPROC=$(command -v nproc >/dev/null 2>&1 && nproc || echo 4)

cmake -B build -S . -DCMAKE_BUILD_TYPE=${BUILD_TYPE} -DBUILD_TESTING=ON
cmake --build build --parallel ${NPROC}
ctest --test-dir build --output-on-failure --timeout 60