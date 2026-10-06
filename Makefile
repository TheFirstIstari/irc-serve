# Makefile — driver for irc-serve
#
# Mirrors `mise.toml` so contributors without mise can drive the build with
# vanilla GNU make. Each target lines up with a step in `local-ci.sh`.

CMAKE ?= cmake
CTEST ?= ctest
NPROC := $(shell nproc 2>/dev/null || echo 4)
BUILD_DIR := build-testing
BENCH_BUILD_DIR := build-benchmark
CTEST_TIMEOUT := 60

.PHONY: all build test benchmark local-ci gate clean help docs-check
.DEFAULT_GOAL := help

help:
	@echo "irc-serve — make targets:"
	@echo "  build        Configure + compile (Release, BUILD_TESTING=ON)"
	@echo "  test         Run unit tests via ctest, then the skip ratchet"
	@echo "  benchmark    Configure + build + run benchmarks"
	@echo "  local-ci     Run ./local-ci.sh (mirrors .github/workflows/ci.yml)"
	@echo "  gate         Run ./scripts/gate.sh — 3 compilers x Release/Debug x"
	@echo "               WITH_TLS ON/OFF, plus an ASan+UBSan cell. SLOW: 13"
	@echo "               fresh builds. Pass extra args, e.g. 'make gate GATE_ARGS=-j2'"
	@echo "  clean        Remove build directories"

# `build` mirrors `local-ci.sh` lines 1-2 and CI job `ci_test`.
build:
	$(CMAKE) -B $(BUILD_DIR) -S . -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
	$(CMAKE) --build $(BUILD_DIR) --parallel $(NPROC)

# `test` mirrors `local-ci.sh` lines 3-4: the suite, then the skip ratchet.
#
# The ratchet is here for the same reason it is in local-ci.sh and in `ci_test`:
# ctest's exit code CANNOT express "a test skipped", so a `make test` that runs
# only ctest is a green run that would have passed with any number of new skips.
# Every entry point that runs the suite runs the gate, or the gate is a gate on
# one path out of three. `ctest ... | tee` is safe here because the recipe is run
# by `sh` and this target is a single pipeline whose status make already takes
# from its LAST command -- tee -- so ctest's own failure is NOT propagated and
# the gate below is what turns a failed suite red. That is a real limitation of
# this target and it is why `make local-ci`, which uses local-ci.sh's pipefail, is
# the one CONTRIBUTING.md tells contributors to run.
test: build
	cd $(BUILD_DIR) && $(CTEST) --output-on-failure --timeout $(CTEST_TIMEOUT) | tee ctest-make.log
	./scripts/check-skips.sh -b $(BUILD_DIR) $(BUILD_DIR)/ctest-make.log
	./scripts/check-attribution.sh
	python3 ./scripts/check-peer-log-sites.py

# `benchmark` mirrors CI job `ci_benchmark`.
benchmark:
	$(CMAKE) -B $(BENCH_BUILD_DIR) -S . -DCMAKE_BUILD_TYPE=Release -DBUILD_BENCHMARK=ON
	$(CMAKE) --build $(BENCH_BUILD_DIR) --parallel $(NPROC)
	cd $(BENCH_BUILD_DIR) && $(CTEST) -L Benchmark --output-on-failure --timeout $(CTEST_TIMEOUT)

# `local-ci` invokes the script designed by the local_ci_design agent.
local-ci:
	@if [ ! -x ./local-ci.sh ]; then \
		echo "[Makefile] local-ci.sh missing or not executable"; \
		exit 1; \
	fi
	./local-ci.sh

# `gate` runs the project's own definition of green: 3 compilers x Release/Debug
# x WITH_TLS ON/OFF (12 cells), plus an ASan+UBSan cell at WITH_TLS=ON. Every
# cell is configured into a FRESH directory and every cell runs ctest, because a
# reused build directory reports success for a file it did not recompile.
#
# It is NOT `local-ci` and does not overlap it: local-ci mirrors ci_test, ONE
# compiler and ONE configuration. The gate is the breadth ci_test deliberately
# does not have. It lives in scripts/gate.sh rather than here because it needs
# per-cell log handling, a compiler probe and a skip ratchet per cell, and a make
# recipe is the wrong place for that.
#
# GATE_ARGS is forwarded verbatim, so `make gate GATE_ARGS=-j2` and
# `make gate GATE_ARGS="--no-asan"` both work.
GATE_ARGS ?=
gate:
	@if [ ! -x ./scripts/gate.sh ]; then \
		echo "[Makefile] scripts/gate.sh missing or not executable"; \
		exit 1; \
	fi
	./scripts/gate.sh $(GATE_ARGS)

clean:
	rm -rf $(BUILD_DIR) $(BENCH_BUILD_DIR) build-gate

docs-check:
	@test -f docs/SPEC_TRACKING.md || (echo "docs/SPEC_TRACKING.md missing"; exit 1)
	@echo "docs check passed"

all: build
