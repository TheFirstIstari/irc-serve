# Makefile — driver for irc-serve
#
# Mirrors `mise.toml` so contributors without mise can drive the build with
# vanilla GNU make. Each target lines up with a step in `local-ci.sh`.

CMAKE ?= cmake
CTEST ?= ctest
NPROC := $(shell nproc 2>/dev/null || echo 4)
BUILD_DIR := build

.PHONY: all build test benchmark local-ci clean help
.DEFAULT_GOAL := help

help:
	@echo "irc-serve — make targets:"
	@echo "  build        Configure + compile (Release, BUILD_TESTING=ON)"
	@echo "  test         Run unit tests via ctest"
	@echo "  benchmark    Configure + build + run benchmarks"
	@echo "  local-ci     Run ./local-ci.sh (mirrors .github/workflows/ci.yml)"
	@echo "  clean        Remove build directories"

# `build` mirrors `local-ci.sh` lines 1-2 and CI job `ci_test`.
build:
	$(CMAKE) -B $(BUILD_DIR) -S . -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
	$(CMAKE) --build $(BUILD_DIR) --parallel $(NPROC)

# `test` mirrors `local-ci.sh` line 3.
test: build
	cd $(BUILD_DIR) && $(CTEST) --output-on-failure --timeout 60

# `benchmark` mirrors CI job `ci_benchmark`.
benchmark:
	$(CMAKE) -B $(BUILD_DIR) -S . -DCMAKE_BUILD_TYPE=Release -DBUILD_BENCHMARK=ON
	$(CMAKE) --build $(BUILD_DIR) --parallel $(NPROC)
	cd $(BUILD_DIR) && $(CTEST) -L Benchmark --output-on-failure

# `local-ci` invokes the script designed by the local_ci_design agent.
local-ci:
	@if [ ! -x ./local-ci.sh ]; then \
		echo "[Makefile] local-ci.sh missing or not executable"; \
		exit 1; \
	fi
	./local-ci.sh

clean:
	rm -rf $(BUILD_DIR) build-release

docs-check:
	@test -f docs/SPEC_TRACKING.md || (echo "docs/SPEC_TRACKING.md missing"; exit 1)
	@echo "docs check passed"

all: build