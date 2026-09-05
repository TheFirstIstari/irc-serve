#!/bin/bash
# local-ci.sh — mirrors .github/workflows/ci.yml (ci_test job).
# Use plain `cmake`/`ctest`; mise.toml [env] prepends mise shims to PATH
# so the pinned toolchain resolves without a `mise run cmake` task.
set -euo pipefail
BRANCH=$(git rev-parse --abbrev-ref HEAD)
echo "[local-ci] Branch: $BRANCH"

cmake -B build -S . -DBUILD_TESTING=ON
cmake --build build --parallel $(nproc)
ctest --test-dir build --output-on-failure